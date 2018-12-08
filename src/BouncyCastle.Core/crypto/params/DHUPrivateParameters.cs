using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.@params
{

	/// <summary>
	/// Parameters holder for private unified static/ephemeral agreement as described in NIST SP 800-56A.
	/// </summary>
	public class DHUPrivateParameters : CipherParameters
	{
		private DHPrivateKeyParameters staticPrivateKey;
		private DHPrivateKeyParameters ephemeralPrivateKey;
		private DHPublicKeyParameters ephemeralPublicKey;

		public DHUPrivateParameters(DHPrivateKeyParameters staticPrivateKey, DHPrivateKeyParameters ephemeralPrivateKey) : this(staticPrivateKey, ephemeralPrivateKey, null)
		{
		}

		public DHUPrivateParameters(DHPrivateKeyParameters staticPrivateKey, DHPrivateKeyParameters ephemeralPrivateKey, DHPublicKeyParameters ephemeralPublicKey)
		{
			if (staticPrivateKey == null)
			{
				throw new NullPointerException("staticPrivateKey cannot be null");
			}
			if (ephemeralPrivateKey == null)
			{
				throw new NullPointerException("ephemeralPrivateKey cannot be null");
			}

			DHParameters parameters = staticPrivateKey.getParameters();
			if (!parameters.Equals(ephemeralPrivateKey.getParameters()))
			{
				throw new IllegalArgumentException("static and ephemeral private keys have different domain parameters");
			}

			if (ephemeralPublicKey == null)
			{
				ephemeralPublicKey = new DHPublicKeyParameters(parameters.getG().modPow(ephemeralPrivateKey.getX(), parameters.getP()), parameters);
			}
			else if (!parameters.Equals(ephemeralPublicKey.getParameters()))
			{
				throw new IllegalArgumentException("ephemeral public key has different domain parameters");
			}

			this.staticPrivateKey = staticPrivateKey;
			this.ephemeralPrivateKey = ephemeralPrivateKey;
			this.ephemeralPublicKey = ephemeralPublicKey;
		}

		public virtual DHPrivateKeyParameters getStaticPrivateKey()
		{
			return staticPrivateKey;
		}

		public virtual DHPrivateKeyParameters getEphemeralPrivateKey()
		{
			return ephemeralPrivateKey;
		}

		public virtual DHPublicKeyParameters getEphemeralPublicKey()
		{
			return ephemeralPublicKey;
		}
	}

}