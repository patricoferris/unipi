open Lwt.Infix

let argument_error = 64

module Main (S: Mirage_stack.V4V6) (C: Mirage_clock.PCLOCK) (M: Mirage_clock.MCLOCK) (Time: Mirage_time.S) (R : Mirage_random.S) = struct

  module TCP = Conduit_mirage_tcp.Make(S)
  module SSH = Awa_conduit.Make(Conduit_mirage.IO)(Conduit_mirage)(M)
  module TLS = Conduit_tls.Make(Conduit_mirage.IO)(Conduit_mirage)

  module RES = Conduit_mirage_dns.Make(R)(Time)(M)(S)

  module Http = Cohttp_mirage.Server_with_conduit

  module Store = Irmin_mirage_git.Mem.KV(Irmin.Contents.String)
  module Sync = Irmin.Sync(Store)

  module Last_modified = struct
    let ptime_to_http_date ptime =
      let (y, m, d), ((hh, mm, ss), _) = Ptime.to_date_time ptime
      and weekday = match Ptime.weekday ptime with
        | `Mon -> "Mon" | `Tue -> "Tue" | `Wed -> "Wed" | `Thu -> "Thu"
        | `Fri -> "Fri" | `Sat -> "Sat" | `Sun -> "Sun"
      and month =
        [| "Jan" ; "Feb" ; "Mar" ; "Apr" ; "May" ; "Jun" ;
           "Jul" ; "Aug" ; "Sep" ; "Oct" ; "Nov" ; "Dec" |]
    in
    let m' = Array.get month (pred m) in
    Printf.sprintf "%s, %02d %s %04d %02d:%02d:%02d GMT" weekday d m' y hh mm ss

    (* cache the last commit (last modified and last hash) *)
    let last = ref ("", "")

    (* cache control: all resources use last-modified + etag of last commit *)
    let retrieve_last_commit store =
      Store.Head.get store >|= fun head ->
      let last_commit_date =
        let info = Store.Commit.info head in
        let ptime =
          match Ptime.of_float_s (Int64.to_float (Irmin.Info.date info)) with
          | None -> Ptime.v (C.now_d_ps ())
          | Some d -> d
        in
        ptime_to_http_date ptime
      and last_commit_hash =
        Fmt.to_to_string (Irmin.Type.pp Store.Hash.t) (Store.Commit.hash head)
      in
      last := (last_commit_date, last_commit_hash)

    let not_modified request =
      let hdr = request.Cohttp.Request.headers in
      match Cohttp.Header.get hdr "if-modified-since" with
      | Some ts -> String.equal ts (fst !last)
      | None -> match Cohttp.Header.get hdr "if-none-match" with
        | Some etags -> List.mem (snd !last) (Astring.String.cuts ~sep:"," etags)
        | None -> false

    let last_modified () = fst !last
    let etag () = snd !last
  end

  module Remote = struct
    let decompose_git_url () =
      match String.split_on_char '#' (Key_gen.remote ()) with
      | [ url ] -> url, None
      | [ url ; branch ] -> url, Some branch
      | _ ->
        Logs.err (fun m -> m "expected at most a single # in remote");
        exit argument_error

    let resolvers stack dns_resolver =
      let remote, _ = decompose_git_url () in
      let resolver, remote =
        let uri = Uri.of_string remote in
        match Uri.host uri with
        | None -> dns_resolver, remote
        | Some host -> match Ipaddr.of_string host with
          | Ok ip ->
            (fun ~port _ ->
               let tcp = Conduit_mirage_tcp.{ stack ; keepalive = None ; nodelay = false ; ip ; port } in
               Lwt.return (Some tcp)),
            Uri.(to_string (with_host uri (Some "reserved")))
          | Error _ -> dns_resolver, remote
      in
      match Smart_git.endpoint_of_string remote, Key_gen.ssh_seed () with
      | Ok { Smart_git.scheme = `SSH user ; path ; _ }, Some key_seed ->
        let authenticator = match Key_gen.ssh_authenticator () with
          | None ->
            Logs.warn (fun m -> m "ssh server will not be authenticated");
            None
          | Some x -> match Awa.Keys.authenticator_of_string x with
            | Ok x -> Some x
            | Error e ->
              Logs.err (fun m -> m "ssh: %s" e);
              exit argument_error
        in
        let key = Awa.Keys.of_seed key_seed in
        (* TODO: what to do with '' in path? *)
        let req = Awa.Ssh.Exec (Fmt.strf "git-upload-pack '%s'" path) in
        let ssh_config = { Awa_conduit.user ; key ; req ; authenticator } in
        let ssh_resolver hostname =
          resolver ~port:22 hostname >|= function
          | Some edn -> Some (edn, ssh_config)
          | None -> None
        in
        remote,
        Conduit_mirage.add
          (SSH.protocol_with_ssh TCP.protocol) ssh_resolver
          Conduit_mirage.empty
      | Ok y, _ ->
        remote,
        Conduit_mirage.add
          TCP.protocol (resolver ~port:9418)
          Conduit_mirage.empty
      | Error (`Msg msg), _ ->
        Logs.err (fun m -> m "git endpoint %s" msg);
        exit argument_error

    let connect stack dns =
      let _, branch = decompose_git_url () in
      let config = Irmin_mem.config () in
      Store.Repo.v config >>= fun r ->
      (match branch with
       | None -> Store.master r
       | Some branch -> Store.of_branch r branch) >|= fun repo ->
      let uri, resolvers = resolvers stack dns in
      repo, Store.remote ~resolvers uri

    let pull store upstream =
      Logs.info (fun m -> m "pulling from remote!");
      Sync.pull store upstream `Set >>= fun r ->
      Last_modified.retrieve_last_commit store >|= fun () ->
      match r with
      | Ok (`Head _ as s) -> Ok (Fmt.strf "pulled %a" Sync.pp_status s)
      | Ok `Empty -> Error (`Msg "pulled empty repository")
      | Error (`Msg e) -> Error (`Msg ("pull error " ^ e))
      | Error (`Conflict msg) -> Error (`Msg ("pull conflict " ^ msg))
  end

  module Dispatch = struct
    let dispatch store hookf hook_url request _body =
      let p = Uri.path (Cohttp.Request.uri request) in
      let path = if String.equal p "/" then "index.html" else p in
      Logs.info (fun f -> f "requested %s" path);
      match Astring.String.cuts ~sep:"/" ~empty:false path with
      | [ h ] when String.equal hook_url h ->
        begin
          hookf () >>= function
          | Ok data -> Http.respond ~status:`OK ~body:(`String data) ()
          | Error (`Msg msg) ->
            Http.respond ~status:`Internal_server_error ~body:(`String msg) ()
        end
      | path_list ->
        if Last_modified.not_modified request then
          Http.respond ~status:`Not_modified ~body:`Empty ()
        else
          Store.find store path_list >>= function
          | Some data ->
            let mime_type = Magic_mime.lookup path in
            let headers = [
              "content-type", mime_type ;
              "etag", Last_modified.etag () ;
              "last-modified", Last_modified.last_modified () ;
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
    module Acme = Letsencrypt.Client.Make(Cohttp_mirage.Client)

    let gen_rsa ?seed () =
      let g = match seed with
        | None -> None
        | Some seed ->
          let seed = Cstruct.of_string seed in
          Some (Mirage_crypto_rng.(create ~seed (module Fortuna)))
      in
      Mirage_crypto_pk.Rsa.generate ?g ~bits:4096 ()

    let csr seed host =
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
          and key = gen_rsa ?seed ()
          in
          key, X509.Signing_request.create cn (`RSA key)

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

    let provision_certificate dns_resolver =
      let open Lwt_result.Infix in
      let endpoint =
        if Key_gen.production () then
          Letsencrypt.letsencrypt_production_url
        else
          Letsencrypt.letsencrypt_staging_url
      and email = Key_gen.email ()
      and seed = Key_gen.account_seed ()
      in
      let ctx =
        Conduit_mirage.add
          TCP.protocol (dns_resolver ~port:80)
          Conduit_mirage.empty
      in
      Acme.initialise ~ctx ~endpoint ?email (gen_rsa ?seed ()) >>= fun le ->
      let sleep sec = Time.sleep_ns (Duration.of_sec sec) in
      let priv, csr = csr (Key_gen.cert_seed ()) (Key_gen.hostname ()) in
      let solver = Letsencrypt.Client.http_solver solver in
      Acme.sign_certificate ~ctx solver le sleep csr >|= fun certs ->
      `Single (certs, priv)
  end

  let serve cb =
    let callback _ request body = cb request body
    and conn_closed _ = ()
    in
    Http.make ~conn_closed ~callback ()

  let start stack () () () () =
    let dns = RES.create stack in
    let dns_resolver ~port =
      RES.resolv stack ?keepalive:None dns ?nameserver:None ~port
    in
    Remote.connect stack dns_resolver >>= fun (store, upstream) ->
    Http.connect TCP.protocol TCP.service >>= fun http ->
    let tls_protocol = TLS.protocol_with_tls TCP.protocol in
    Http.connect tls_protocol (TLS.service_with_tls TCP.service tls_protocol) >>= fun https ->
    Lwt.map
      (function Ok () -> Lwt.return_unit | Error (`Msg msg) -> Lwt.fail_with msg)
      (let open Lwt_result.Infix in
       Remote.pull store upstream >>= fun data ->
       Logs.info (fun m -> m "store: %s" data);
       let http_port = Key_gen.port () in
       let tcp = `TCP http_port in
       let server =
         let hook_url = Key_gen.hook () in
         if Astring.String.is_infix ~affix:"/" hook_url then begin
           Logs.err (fun m -> m "hook url contains /, which is not allowed");
           exit argument_error
         end else
           let hookf () = Remote.pull store upstream in
           serve (Dispatch.dispatch store hookf hook_url)
       in
       let port = 80 in
       let tcp = Conduit_mirage_tcp.{ stack ; keepalive = None ; nodelay = false ; port = 80 } in
       if Key_gen.tls () then begin
         let rec provision () =
           Logs.info (fun m ->
               m "listening on HTTP for let's encrypt provisioning");
           (* this should be cancelled once certificates are retrieved *)
           Lwt.async (fun () -> http tcp (serve LE.dispatch));
           LE.provision_certificate dns_resolver >>= fun certificates ->
           let tls_cfg = Tls.Config.server ~certificates () in
           let port = 443 in
           let tls = Conduit_mirage_tcp.{ stack ; keepalive = None ; nodelay = false ; port } in
           let https =
             Logs.info (fun f -> f "listening on HTTPS port");
             https (tls, tls_cfg) server
           and http =
             Logs.info (fun f -> f "listening on HTTP, redirecting to HTTPS");
             let redirect = serve (Dispatch.redirect port) in
             http tcp redirect
           in
           let expire = Time.sleep_ns (Duration.of_day 80) in
           Lwt_result.ok (Lwt.pick [ https; http; expire ]) >>= fun () ->
           provision ()
         in
         provision ()
       end else begin
         Logs.info (fun f -> f "listening on HTTP");
         Lwt_result.ok (http tcp server)
       end)
end
