export function validateRequestShape(req) {
  const id = req?.id;
  if (typeof id !== "string" || !id) {
    return {
      ok: false,
      id: typeof id === "string" ? id : "",
      error: {
        code: "bad_request",
        message: "id must be a non-empty string",
      },
    };
  }
  const operation = req?.operation;
  if (typeof operation !== "string" || !operation) {
    return {
      ok: false,
      id,
      error: {
        code: "bad_request",
        message: "operation must be a non-empty string",
      },
    };
  }
  if (
    req?.payload !== undefined &&
    (typeof req.payload !== "object" || req.payload === null || Array.isArray(req.payload))
  ) {
    return {
      ok: false,
      id,
      error: {
        code: "bad_request",
        message: "payload must be an object when provided",
      },
    };
  }
  return { ok: true, id, operation, payload: req.payload ?? {} };
}

export function rejectsPrivateJwkMaterial(jwk) {
  return (
    jwk &&
    typeof jwk === "object" &&
    Object.prototype.hasOwnProperty.call(jwk, "d")
  );
}

export function publicPrepareError(err) {
  if (process.env.SWIYU_OPENAC_DEBUG === "1") {
    console.error("[openac-debug]", err);
  }
  return {
    code: "bad_credential",
    message:
      "credential could not be parsed or prepared (issuer signature and trust are not verified by prepare)",
  };
}
