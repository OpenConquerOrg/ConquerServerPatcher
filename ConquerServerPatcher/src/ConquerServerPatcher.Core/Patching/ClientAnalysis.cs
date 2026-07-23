namespace ConquerRsaTool.Core.Patching;

public sealed record ClientAnalysis(bool Supported, string Message, IReadOnlyList<int> ModulusOffsets, bool IsContiguous);
public sealed record PatchResult(string OutputPath, bool PlayExeBypassApplied, string PlayExeBypassMessage);
