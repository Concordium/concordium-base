# Changes for Notabene

The `token` in the return value should not be URLencoded, it should just be plain JSON.

The initial request should be a POST request with content-type application/json. The body should contain a JSON object
of the form
{
    "idObjectRequest": {..}
    "redirectURI": "..."
}