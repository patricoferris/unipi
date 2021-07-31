open Lwt.Infix
let argument_error = 64

module Main (_ : sig end) (Http_client: Cohttp_lwt.S.Client) (Http: Cohttp_mirage.Server.S) (FS: Mirage_kv.RO) (C: Mirage_clock.PCLOCK) (Time: Mirage_time.S) = struct

  let fs_read dev name =
    FS.get dev (Mirage_kv.Key.v name) >|= function
    | Ok data -> Some data
    | Error e -> 
      Logs.warn (fun f -> f "%a" FS.pp_error e);
      None
  
  module Dispatch = struct
    let dispatch store request _body =
      let p = Uri.path (Cohttp.Request.uri request) in
      let path = if String.equal p "/" then "index.html" else p in
      Logs.info (fun f -> f "requested %s" path);
        fs_read store path >>= function
        | Some data ->
          let mime_type = Magic_mime.lookup path in
          let headers = [
            "content-type", mime_type ;
          ] in
          let headers = Cohttp.Header.of_list headers in
          Http.respond ~headers ~status:`OK ~body:(`String data) ()
        | None ->
          let data = "Resource not found " ^ path in
          Http.respond ~status:`Not_found ~body:(`String data) ()

    let redirect port request _body =
      let uri = Cohttp.Request.uri request in
      let new_uri = Uri.with_scheme uri (Some "https") in
      let port = if port = 443 then None else Some port in
      let new_uri = Uri.with_port new_uri port in
      Logs.info (fun f -> f "[%s] -> [%s]"
                    (Uri.to_string uri) (Uri.to_string new_uri));
      let headers =
        Cohttp.Header.init_with "location" (Uri.to_string new_uri)
      in
      Http.respond ~headers ~status:`Moved_permanently ~body:`Empty ()
  end

  module LE = struct
    module Acme = Letsencrypt.Client.Make(Http_client)

    let gen_rsa ?seed () =
      let g = match seed with
        | None -> None
        | Some seed ->
          let seed = Cstruct.of_string seed in
          Some (Mirage_crypto_rng.(create ~seed (module Fortuna)))
      in
      Mirage_crypto_pk.Rsa.generate ?g ~bits:4096 ()

    let csr key host =
      match host with
      | None ->
        Logs.err (fun m -> m "no hostname provided");
        exit argument_error
      | Some host ->
        match Domain_name.of_string host with
        | Error `Msg err ->
          Logs.err (fun m -> m "invalid hostname provided %s" err);
          exit argument_error
        | Ok _ ->
          let cn =
            X509.[Distinguished_name.(Relative_distinguished_name.singleton (CN host))]
          in
          X509.Signing_request.create cn key

    let prefix = ".well-known", "acme-challenge"
    let tokens = Hashtbl.create 1

    let solver _host ~prefix:_ ~token ~content =
      Hashtbl.replace tokens token content;
      Lwt.return (Ok ())

    let dispatch request _body =
      let path = Uri.path (Cohttp.Request.uri request) in
      Logs.info (fun m -> m "let's encrypt dispatcher %s" path);
      match Astring.String.cuts ~sep:"/" ~empty:false path with
      | [ p1; p2; token ] when
          String.equal p1 (fst prefix) && String.equal p2 (snd prefix) ->
        begin
          match Hashtbl.find_opt tokens token with
          | Some data ->
            let headers =
              Cohttp.Header.init_with "content-type" "application/octet-stream"
            in
            Http.respond ~headers ~status:`OK ~body:(`String data) ()
          | None -> Http.respond ~status:`Not_found ~body:`Empty ()
        end
      | _ -> Http.respond ~status:`Not_found ~body:`Empty ()

    let provision_certificate ctx =
      let open Lwt_result.Infix in
      let endpoint =
        if Key_gen.production () then
          Letsencrypt.letsencrypt_production_url
        else
          Letsencrypt.letsencrypt_staging_url
      and email = Key_gen.email ()
      and seed = Key_gen.account_seed ()
      in
      let priv = `RSA (gen_rsa ?seed:(Key_gen.cert_seed ()) ()) in
      match csr priv (Key_gen.hostname ()) with
      | Error (`Msg err) ->
        Logs.err (fun m -> m "couldn't create signing request %s" err);
        exit argument_error
      | Ok csr ->
        Acme.initialise ~ctx ~endpoint ?email (gen_rsa ?seed ()) >>= fun le ->
        let sleep sec = Time.sleep_ns (Duration.of_sec sec) in
        let solver = Letsencrypt.Client.http_solver solver in
        Acme.sign_certificate ~ctx solver le sleep csr >|= fun certs ->
        `Single (certs, priv)
  end

  let serve cb =
    let callback _ request body = cb request body
    and conn_closed _ = ()
    in
    Http.make ~conn_closed ~callback ()

  let start ctx http_client http store () () =
    Lwt.map
      (function Ok () -> Lwt.return_unit | Error (`Msg msg) -> Lwt.fail_with msg)
      (let open Lwt_result.Infix in
       let http_port = Key_gen.port () in
       let tcp = `TCP http_port in
       let server =
         serve (Dispatch.dispatch store)
       in
       if Key_gen.tls () then begin
         let rec provision () =
           Logs.info (fun m ->
               m "listening on 80/HTTP (let's encrypt provisioning)");
           (* this should be cancelled once certificates are retrieved *)
           Lwt.async (fun () -> http (`TCP 80) (serve LE.dispatch));
           LE.provision_certificate http_client >>= fun certificates ->
           let tls_cfg = Tls.Config.server ~certificates () in
           let https_port = 443 in
           let tls = `TLS (tls_cfg, `TCP https_port) in
           let https =
             Logs.info (fun f -> f "listening on %d/HTTPS" https_port);
             http tls server
           and http =
             Logs.info (fun f -> f "listening on %d/HTTP, redirecting to %d/HTTPS"
                           http_port https_port);
             let redirect = serve (Dispatch.redirect https_port) in
             http tcp redirect
           in
           let expire = Time.sleep_ns (Duration.of_day 80) in
           Lwt_result.ok (Lwt.pick [ https; http; expire ]) >>= fun () ->
           provision ()
         in
         provision ()
       end else begin
         Logs.info (fun f -> f "listening on %d/HTTP" http_port);
         Lwt_result.ok (http tcp server)
       end)
end
