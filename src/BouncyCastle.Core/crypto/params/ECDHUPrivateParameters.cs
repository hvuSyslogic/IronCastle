using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.@params
{

	/// <summary>
	/// Parameters holder for private unified static/ephemeral agreement as described in NIST SP 800-56A.
	/// </summary>
	public class ECDHUPrivateParameters : CipherParameters
	{
		private ECPrivateKeyParameters staticPrivateKey;
		private ECPrivateKeyParameters ephemeralPrivateKey;
		private ECPublicKeyParameters ephemeralPublicKey;

		public ECDHUPrivateParameters(ECPrivateKeyParameters staticPrivateKey, ECPrivateKeyParameters ephemeralPrivateKey) : this(staticPrivateKey, ephemeralPrivateKey, null)
		{
		}

		public ECDHUPrivateParameters(ECPrivateKeyParameters staticPrivateKey, ECPrivateKeyParameters ephemeralPrivateKey, ECPublicKeyParameters ephemeralPublicKey)
		{
			if (staticPrivateKey == null)
			{
				throw new NullPointerException("staticPrivateKey cannot be null");
			}
			if (ephemeralPrivateKey == null)
			{
				throw new NullPointerException("ephemeralPrivateKey cannot be null");
			}

			ECDomainParameters parameters = staticPrivateKey.getParameters();
			if (!parameters.Equals(ephemeralPrivateKey.getParameters()))
			{
				throw new IllegalArgumentException("static and ephemeral private keys have different domain parameters");
			}

			if (ephemeralPublicKey == null)
			{
				ephemeralPublicKey = new ECPublicKeyParameters(parameters.getG().multiply(ephemeralPrivateKey.getD()), parameters);
			}
			else if (!parameters.Equals(ephemeralPublicKey.getParameters()))
			{
				throw new IllegalArgumentException("ephemeral public key has different domain parameters");
			}

			this.staticPrivateKey = staticPrivateKey;
			this.ephemeralPrivateKey = ephemeralPrivateKey;
			this.ephemeralPublicKey = ephemeralPublicKey;
		}

		public virtual ECPrivateKeyParameters getStaticPrivateKey()
		{
			return staticPrivateKey;
		}

		public virtual ECPrivateKeyParameters getEphemeralPrivateKey()
		{
			return ephemeralPrivateKey;
		}

		public virtual ECPublicKeyParameters getEphemeralPublicKey()
		{
			return ephemeralPublicKey;
		}
	}

}