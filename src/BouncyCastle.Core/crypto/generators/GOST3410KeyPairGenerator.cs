﻿using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.math.ec;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.generators
{

						
	/// <summary>
	/// a GOST3410 key pair generator.
	/// This generates GOST3410 keys in line with the method described
	/// in GOST R 34.10-94.
	/// </summary>
	public class GOST3410KeyPairGenerator : AsymmetricCipherKeyPairGenerator
	{
			private GOST3410KeyGenerationParameters param;

			public virtual void init(KeyGenerationParameters param)
			{
				this.param = (GOST3410KeyGenerationParameters)param;
			}

			public virtual AsymmetricCipherKeyPair generateKeyPair()
			{
				BigInteger p, q, a, x, y;
				GOST3410Parameters GOST3410Params = param.getParameters();
				SecureRandom random = param.getRandom();

				q = GOST3410Params.getQ();
				p = GOST3410Params.getP();
				a = GOST3410Params.getA();

				int minWeight = 64;
				for (;;)
				{
					x = BigIntegers.createRandomBigInteger(256, random);

					if (x.signum() < 1 || x.compareTo(q) >= 0)
					{
						continue;
					}

					if (WNafUtil.getNafWeight(x) < minWeight)
					{
						continue;
					}

					break;
				}

				//
				// calculate the public key.
				//
				y = a.modPow(x, p);

				return new AsymmetricCipherKeyPair(new GOST3410PublicKeyParameters(y, GOST3410Params), new GOST3410PrivateKeyParameters(x, GOST3410Params));
			}
	}

}