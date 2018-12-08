using BouncyCastle.Core.Port;
using org.bouncycastle.Port;

namespace org.bouncycastle.pqc.crypto.sphincs
{

	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using AsymmetricCipherKeyPairGenerator = org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
	using Digest = org.bouncycastle.crypto.Digest;
	using KeyGenerationParameters = org.bouncycastle.crypto.KeyGenerationParameters;

	public class SPHINCS256KeyPairGenerator : AsymmetricCipherKeyPairGenerator
	{
		private SecureRandom random;
		private Digest treeDigest;

		public virtual void init(KeyGenerationParameters param)
		{
			random = param.getRandom();
			treeDigest = ((SPHINCS256KeyGenerationParameters)param).getTreeDigest();
		}

		public virtual AsymmetricCipherKeyPair generateKeyPair()
		{
			Tree.leafaddr a = new Tree.leafaddr();

			byte[] sk = new byte[SPHINCS256Config.CRYPTO_SECRETKEYBYTES];

			random.nextBytes(sk);

			byte[] pk = new byte[SPHINCS256Config.CRYPTO_PUBLICKEYBYTES];

			JavaSystem.arraycopy(sk, SPHINCS256Config.SEED_BYTES, pk, 0, Horst.N_MASKS * SPHINCS256Config.HASH_BYTES);

			// Initialization of top-subtree address
			a.level = SPHINCS256Config.N_LEVELS - 1;
			a.subtree = 0;
			a.subleaf = 0;

			HashFunctions hs = new HashFunctions(treeDigest);

			// Format pk: [|N_MASKS*params.HASH_BYTES| Bitmasks || root]
			// Construct top subtree
			Tree.treehash(hs, pk, (Horst.N_MASKS * SPHINCS256Config.HASH_BYTES), SPHINCS256Config.SUBTREE_HEIGHT, sk, a, pk, 0);

			return new AsymmetricCipherKeyPair(new SPHINCSPublicKeyParameters(pk), new SPHINCSPrivateKeyParameters(sk));
		}
	}

}