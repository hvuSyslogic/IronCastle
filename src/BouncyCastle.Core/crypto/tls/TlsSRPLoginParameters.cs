using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.tls
{

	using SRP6GroupParameters = org.bouncycastle.crypto.@params.SRP6GroupParameters;

	public class TlsSRPLoginParameters
	{
		protected internal SRP6GroupParameters group;
		protected internal BigInteger verifier;
		protected internal byte[] salt;

		public TlsSRPLoginParameters(SRP6GroupParameters group, BigInteger verifier, byte[] salt)
		{
			this.group = group;
			this.verifier = verifier;
			this.salt = salt;
		}

		public virtual SRP6GroupParameters getGroup()
		{
			return group;
		}

		public virtual byte[] getSalt()
		{
			return salt;
		}

		public virtual BigInteger getVerifier()
		{
			return verifier;
		}
	}

}