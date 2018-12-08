namespace org.bouncycastle.pqc.crypto.newhope
{
	public class Params
	{
		internal const int N = 1024;
		internal const int K = 16; // used in sampler
		internal const int Q = 12289;

		internal const int POLY_BYTES = 1792;
		internal const int REC_BYTES = 256;
		internal const int SEED_BYTES = 32; // care changing this one - connected to digest size used.
	}

}