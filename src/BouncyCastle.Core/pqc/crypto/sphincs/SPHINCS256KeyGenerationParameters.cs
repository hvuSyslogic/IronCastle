using BouncyCastle.Core.Port;
using org.bouncycastle.crypto;

namespace org.bouncycastle.pqc.crypto.sphincs
{

		
	public class SPHINCS256KeyGenerationParameters : KeyGenerationParameters
	{
		private readonly Digest treeDigest;

		public SPHINCS256KeyGenerationParameters(SecureRandom random, Digest treeDigest) : base(random, SPHINCS256Config.CRYPTO_PUBLICKEYBYTES * 8)
		{
			this.treeDigest = treeDigest;
		}

		public virtual Digest getTreeDigest()
		{
			return treeDigest;
		}
	}

}