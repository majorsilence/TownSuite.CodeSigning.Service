namespace TownSuite.CodeSigning.Service
{
    public class Settings
    {
        public string SignToolPath { get; init; }
        public string SignToolOptions { get; init; }
        public string SignToolDetachedOptions { get; init; }
        public int SigntoolTimeoutInMs { get; init; }
        public long MaxRequestBodySize { get; init; }
    }
}
