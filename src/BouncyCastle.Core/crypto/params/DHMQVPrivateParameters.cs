﻿using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.@params
{

	public class DHMQVPrivateParameters : CipherParameters
	{
		private DHPrivateKeyParameters staticPrivateKey;
		private DHPrivateKeyParameters ephemeralPrivateKey;
		private DHPublicKeyParameters ephemeralPublicKey;

		public DHMQVPrivateParameters(DHPrivateKeyParameters staticPrivateKey, DHPrivateKeyParameters ephemeralPrivateKey) : this(staticPrivateKey, ephemeralPrivateKey, null)
		{
		}

		public DHMQVPrivateParameters(DHPrivateKeyParameters staticPrivateKey, DHPrivateKeyParameters ephemeralPrivateKey, DHPublicKeyParameters ephemeralPublicKey)
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
				throw new IllegalArgumentException("Static and ephemeral private keys have different domain parameters");
			}

			if (ephemeralPublicKey == null)
			{
				ephemeralPublicKey = new DHPublicKeyParameters(parameters.getG().multiply(ephemeralPrivateKey.getX()), parameters);
			}
			else if (!parameters.Equals(ephemeralPublicKey.getParameters()))
			{
				throw new IllegalArgumentException("Ephemeral public key has different domain parameters");
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