namespace Neo4j.AspNet.Identity
{
    public static class Relationship
    {
        public const string HasLogin = "HAS_LOGIN";
        public const string HasClaim = "HAS_CLAIM";
    }

    public static class Labels
    {
        public const string Login = "Login";
        public const string User = "User";
        public const string Claim = "Claim";
    }
}