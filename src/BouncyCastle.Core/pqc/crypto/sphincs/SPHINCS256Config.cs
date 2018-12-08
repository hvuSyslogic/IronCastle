namespace org.bouncycastle.pqc.crypto.sphincs
{
	public class SPHINCS256Config
	{
		internal const int SUBTREE_HEIGHT = 5;
		internal const int TOTALTREE_HEIGHT = 60;
		internal static readonly int N_LEVELS = (TOTALTREE_HEIGHT / SUBTREE_HEIGHT);
		internal const int SEED_BYTES = 32;

		internal const int SK_RAND_SEED_BYTES = 32;
		internal const int MESSAGE_HASH_SEED_BYTES = 32;

		internal const int HASH_BYTES = 32; // Has to be log(HORST_T)*HORST_K/8
		internal const int MSGHASH_BYTES = 64;

		internal static readonly int CRYPTO_PUBLICKEYBYTES = ((Horst.N_MASKS + 1) * HASH_BYTES);
		internal static readonly int CRYPTO_SECRETKEYBYTES = (SEED_BYTES + CRYPTO_PUBLICKEYBYTES - HASH_BYTES + SK_RAND_SEED_BYTES);
		internal static readonly int CRYPTO_BYTES = (MESSAGE_HASH_SEED_BYTES + (TOTALTREE_HEIGHT + 7) / 8 + Horst.HORST_SIGBYTES + (TOTALTREE_HEIGHT / SUBTREE_HEIGHT) * Wots.WOTS_SIGBYTES + TOTALTREE_HEIGHT * HASH_BYTES);
	}

}