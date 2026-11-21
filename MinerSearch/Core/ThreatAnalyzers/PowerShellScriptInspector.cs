using DBase;
using MSearch;
using System;
using System.IO;
using System.Text;
using System.Threading;

namespace MSearch.Core.ThreatAnalyzers
{
    public sealed class PowerShellScriptInspector
    {
        private const int MaxScriptChars = 256 * 1024;
        private const int MaliciousThreshold = 7;
        private const int SuspiciousThreshold = 4;

        public PowerShellScriptAnalysisResult Analyze(string scriptPath, CancellationToken token)
        {
            return Analyze(scriptPath, null, token);
        }

        public PowerShellScriptAnalysisResult Analyze(string scriptPath, string commandLine, CancellationToken token)
        {
            if (string.IsNullOrWhiteSpace(scriptPath))
                return PowerShellScriptAnalysisResult.Empty;

            return AnalyzeCore(scriptPath, commandLine, token);
        }

        private PowerShellScriptAnalysisResult AnalyzeCore(string scriptPath, string commandLine, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();

            string text;
            try
            {
                text = ReadScript(scriptPath, token);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                return PowerShellScriptAnalysisResult.ReadError();
            }

            int score = 0;

            if (ContainsAny(text, MSKeys.PowerShellInjectionMarkers))
                score += 4;

            if (ContainsAny(text, MSKeys.PowerShellMinerMarkers))
                score += 4;

            if (ContainsAny(text, MSKeys.PowerShellDownloadMarkers))
                score += 3;

            if (ContainsAny(text, MSKeys.PowerShellPersistenceMarkers))
                score += 3;

            if (ContainsAny(text, MSKeys.PowerShellTamperMarkers))
                score += 3;

            if (ContainsAny(text, MSKeys.PowerShellPrivilegeMarkers))
                score += 2;

            if (ContainsAny(text, MSKeys.PowerShellAntiDetectMarkers))
                score += 2;

            if (ContainsAny(text, MSKeys.PowerShellSignatureBlockMarkers))
                score -= 2;

            int pathScore = GetPathScore(scriptPath);
            score += pathScore;

            if (pathScore > 0 && HasHiddenWindowAndBypass(commandLine))
                score += 1;

            if (score < 0)
                score = 0;

            return new PowerShellScriptAnalysisResult(score, score >= MaliciousThreshold, score >= SuspiciousThreshold);
        }

        private static string ReadScript(string scriptPath, CancellationToken token)
        {
            string path = scriptPath;
            if (path.Length >= 248 && !path.StartsWith(@"\\?\", StringComparison.Ordinal))
                path = @"\\?\" + path;

            using (FileStream stream = FileChecker.OpenReadWithFallback(path, FileShare.Read))
            using (var reader = new StreamReader(stream, Encoding.UTF8, true))
            {
                char[] buffer = new char[MaxScriptChars];
                int length = 0;

                while (length < buffer.Length)
                {
                    token.ThrowIfCancellationRequested();

                    int read = reader.Read(buffer, length, buffer.Length - length);
                    if (read <= 0)
                        break;

                    length += read;
                }

                return new string(buffer, 0, length);
            }
        }

        private static bool ContainsAny(string text, string key)
        {
            string[] markers = MSData.GetInstance.markerSets[key];
            return MSData.ContainsAnyMarker(text, markers);
        }

        private static bool HasHiddenWindowAndBypass(string commandLine)
        {
            if (string.IsNullOrEmpty(commandLine))
                return false;

            bool hidden = ContainsAny(commandLine, MSKeys.PowerShellHiddenMarkers);
            bool bypass = ContainsAny(commandLine, MSKeys.PowerShellBypassMarkers);

            return hidden && bypass;
        }

        private static int GetPathScore(string scriptPath)
        {
            int score = 0;
            string normalizedPath = scriptPath.Replace('/', '\\');

            if (MSData.ContainsAnyMarker(normalizedPath, MSData.GetInstance.markerSets[MSKeys.PowerShellMasqueradeMarkers]) &&
                !ContainsAny(normalizedPath, MSKeys.PowerShellDefenderPathMarkers))
                score += 2;

            try
            {
                if (FileSystemManager.HasHiddenAndSystemAttributes(scriptPath))
                    score += 1;
            }
            catch { }

            return score;
        }
    }

    public sealed class PowerShellScriptAnalysisResult
    {
        public static readonly PowerShellScriptAnalysisResult Empty = new PowerShellScriptAnalysisResult(0, false, false);

        public int Score { get; }
        public bool IsMalicious { get; }
        public bool IsSuspicious { get; }
        public bool HasReadError { get; }

        public PowerShellScriptAnalysisResult(int score, bool isMalicious, bool isSuspicious)
        {
            Score = score;
            IsMalicious = isMalicious;
            IsSuspicious = isSuspicious && !isMalicious;
            HasReadError = false;
        }

        private PowerShellScriptAnalysisResult(bool readError)
        {
            Score = 0;
            IsMalicious = false;
            IsSuspicious = false;
            HasReadError = readError;
        }

        public static PowerShellScriptAnalysisResult ReadError()
        {
            return new PowerShellScriptAnalysisResult(true);
        }
    }
}
