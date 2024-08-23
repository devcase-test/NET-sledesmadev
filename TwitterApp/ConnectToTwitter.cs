using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography;
using System.Text;

public class ConnectToTwitter
{
    public string ConsumerKey { get; set; }
    public string ConsumerSecret { get; set; }
    public string AccessToken { get; set; }
    public string AccessTokenSecret { get; set; }

    public Dictionary<string, string> Parameters { get; set; }

    public string ApiUrl { get; set; }

    const string Method = "GET";

    public WebRequest CreateRequest()
    {
        string encodedParams = EncodeParameters(Parameters);

        var request = WebRequest.Create(string.Format("{0}?{1}", ApiUrl, encodedParams));
        request.Method = Method;
        request.ContentType = "application/x-www-form-urlencoded";
        request.Headers.Add(
            "Authorization",
            MakeOAuthHeader(ConsumerKey, ConsumerSecret, AccessToken, AccessTokenSecret, Method, ApiUrl, Parameters));

        return request;
    }

    static string EncodeParameters(Dictionary<string, string> parameters)
    {
        if (parameters.Count == 0)
            return string.Empty;
        Dictionary<string, string>.KeyCollection.Enumerator keys = parameters.Keys.GetEnumerator();
        keys.MoveNext();
        StringBuilder sb = new StringBuilder(
            string.Format("{0}={1}", keys.Current, Uri.EscapeDataString(parameters[keys.Current])));
        while (keys.MoveNext())
            sb.AppendFormat("&{0}={1}", keys.Current, Uri.EscapeDataString(parameters[keys.Current]));
        return sb.ToString();
    }

    static string MakeOAuthHeader(string consumerKey, string consumerSecret, string accessToken, string accessKey,
        string method, string url, Dictionary<string, string> parameters)
    {
        TimeSpan ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        string oauth_consumer_key = consumerKey;
        string oauth_nonce = Convert.ToBase64String(new ASCIIEncoding().GetBytes(DateTime.Now.Ticks.ToString()));
        string oauth_signature_method = "HMAC-SHA1";
        string oauth_token = accessToken;
        string oauth_timestamp = Convert.ToInt64(ts.TotalSeconds).ToString();
        string oauth_version = "1.0";

        SortedDictionary<string, string> sd = new SortedDictionary<string, string>();
        if (parameters != null)
            foreach (string key in parameters.Keys)
                sd.Add(key, Uri.EscapeDataString(parameters[key]));
        sd.Add("oauth_version", oauth_version);
        sd.Add("oauth_consumer_key", oauth_consumer_key);
        sd.Add("oauth_nonce", oauth_nonce);
        sd.Add("oauth_signature_method", oauth_signature_method);
        sd.Add("oauth_timestamp", oauth_timestamp);
        sd.Add("oauth_token", oauth_token);

        StringBuilder sb = new StringBuilder();
        sb.AppendFormat("{0}&{1}&", method, Uri.EscapeDataString(url));
        foreach (KeyValuePair<string, string> entry in sd)
            sb.Append(Uri.EscapeDataString(string.Format("{0}={1}&", entry.Key, entry.Value)));
        string baseString = sb.ToString().Substring(0, sb.Length - 3);

        string oauth_token_secret = accessKey;
        string signingKey = string.Format(
            "{0}&{1}", Uri.EscapeDataString(consumerSecret), Uri.EscapeDataString(oauth_token_secret));
        HMACSHA1 hasher = new HMACSHA1(new ASCIIEncoding().GetBytes(signingKey));
        string oauth_signature = Convert.ToBase64String(hasher.ComputeHash(new ASCIIEncoding().GetBytes(baseString)));

        sb = new StringBuilder("OAuth ");
        sb.AppendFormat("oauth_consumer_key=\"{0}\",", Uri.EscapeDataString(oauth_consumer_key));
        sb.AppendFormat("oauth_nonce=\"{0}\",", Uri.EscapeDataString(oauth_nonce));
        sb.AppendFormat("oauth_signature=\"{0}\",", Uri.EscapeDataString(oauth_signature));
        sb.AppendFormat("oauth_signature_method=\"{0}\",", Uri.EscapeDataString(oauth_signature_method));
        sb.AppendFormat("oauth_timestamp=\"{0}\",", Uri.EscapeDataString(oauth_timestamp));
        sb.AppendFormat("oauth_token=\"{0}\",", Uri.EscapeDataString(oauth_token));
        sb.AppendFormat("oauth_version=\"{0}\"", Uri.EscapeDataString(oauth_version));

        return sb.ToString();
    }
}