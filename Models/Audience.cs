namespace jWtTokenWebApi.Models
{
    public class Audience
    {
        public string Secret { get; set; }
        public string Iss { get; set; }
        public string Aud { get; set; }
        public string[] roles { get; set; }
        public string Times { get; set; }
    }
}
