import debugFactory from "debug";
import { Router } from "express";
import { setSessionCookie, clearSessionCookie } from "./cookie";
import { serialize } from "./session";
import { getDomain } from "./middleware";
import {
  serializeAuthState,
  deserializeAuthState,
  setAuthStateCookie,
  getAuthStateCookie,
} from "./state";

const debug = debugFactory("myapp:routes");
const { generators } = require('openid-client');
const code_verifier = generators.codeVerifier();
/*
  This is a simple middleware that hosts all the routes
  necessary to manage authentication. In here you are going
  to see the vital routes:
  - auth/login which inits the whole oAuth flow
  - auth/callback which is the thing that the openId provider will call to finish the auth process


  We are also including a logout route and others might be included
  such as a `userinfo` proxy among others.

 */
export default function authRoutesMiddleware(): Router {
  const router = Router();

  //1. RP send request to openid provider
  router.get("/auth/login", function (req, res, next) {
    const backToPath = (req.query.backTo as string) || "/private";
    const state = serializeAuthState({ backToPath });
    const code_challenge = generators.codeChallenge(code_verifier);

    const authUrl = req.app.authClient!.authorizationUrl({
      scope: "openid email profile", 
      //state, 
      code_challenge,
      code_challenge_method:"S256"
    });

    debug("setting state cookie %O", state);
    setAuthStateCookie(res, state);

    console.log(authUrl);
    debug("redirecting to %s", authUrl);
    res.redirect(authUrl);
  });

  router.get("/auth/callback", async (req, res, next) => {
    debug("/auth/callback");
    try {
      console.log("req.cookies", req.cookies);
      const state = getAuthStateCookie(req);
      debug("state %s", state);
      const { backToPath } = deserializeAuthState(state);
      debug("state %O", deserializeAuthState(state));
      const client = req.app.authClient;

      //3. Openid Provider return code และ state
      const params = client!.callbackParams(req);
      console.log("params");
      console.log(params);
      //4.1 RP ส่ง request เพื่อขอ Token
      const tokenSet = await client!.callback(
        `${getDomain()}/auth/callback`,
        params, 
        //{ state },
        { code_verifier }
        
      );

      //4.2 RP ส่ง request มาเพื่อ Get UserInfo
      const user = await client!.userinfo(tokenSet);
      //5. OP return claims ของ user กลับมาให้
      console.log("userClaims");
      console.log(user);

      const sessionCookie = serialize({ tokenSet, user });
      setSessionCookie(res, sessionCookie);

      res.redirect(backToPath);
    } catch (err) {
      console.log("SOMETHING WENT WRONG", err);
      return next(err);
    }
  });

  // This is a logout mostly local to our app, that means
  // that your session with the identity provider will be ketp intact.
  router.get("/auth/logout", async (req, res, next) => {
    const client = req.app.authClient;
    const tokenSet = req.session?.tokenSet;

    try {
      await client!.revoke(tokenSet!.access_token!);
    } catch (err) {
      console.error("error revoking access_token", err);
    }
    clearSessionCookie(res);

    res.redirect("/");
  });

  // This does not work, it looks like google doesn't provider
  // the necessary endpoints in the Discovery doc
  router.get("/auth/logout/sso", async (req, res, next) => {
    const client = req.app.authClient;
    const tokenSet = req.session?.tokenSet;

    clearSessionCookie(res);

    const endSessionUrl = client!.endSessionUrl();
    res.redirect(endSessionUrl);
  });

  return router;
}
