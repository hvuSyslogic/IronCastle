using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.generators
{

					
	/// <summary>
	/// a Cramer Shoup key pair generator
	/// 
	/// </summary>
	public class CramerShoupKeyPairGenerator : AsymmetricCipherKeyPairGenerator
	{

		private static readonly BigInteger ONE = BigInteger.valueOf(1);

		private CramerShoupKeyGenerationParameters param;

		public virtual void init(KeyGenerationParameters param)
		{
			this.param = (CramerShoupKeyGenerationParameters) param;
		}

		public virtual AsymmetricCipherKeyPair generateKeyPair()
		{
			CramerShoupParameters csParams = param.getParameters();

			CramerShoupPrivateKeyParameters sk = generatePrivateKey(param.getRandom(), csParams);
			CramerShoupPublicKeyParameters pk = calculatePublicKey(csParams, sk);
			sk.setPk(pk);

			return new AsymmetricCipherKeyPair(pk, sk);
		}

		private BigInteger generateRandomElement(BigInteger p, SecureRandom random)
		{
			return BigIntegers.createRandomInRange(ONE, p.subtract(ONE), random);
		}

		private CramerShoupPrivateKeyParameters generatePrivateKey(SecureRandom random, CramerShoupParameters csParams)
		{
			BigInteger p = csParams.getP();
			CramerShoupPrivateKeyParameters key = new CramerShoupPrivateKeyParameters(csParams, generateRandomElement(p, random), generateRandomElement(p, random), generateRandomElement(p, random), generateRandomElement(p, random), generateRandomElement(p, random));
			return key;
		}

		private CramerShoupPublicKeyParameters calculatePublicKey(CramerShoupParameters csParams, CramerShoupPrivateKeyParameters sk)
		{
			BigInteger g1 = csParams.getG1();
			BigInteger g2 = csParams.getG2();
			BigInteger p = csParams.getP();

			BigInteger c = g1.modPow(sk.getX1(), p).multiply(g2.modPow(sk.getX2(), p));
			BigInteger d = g1.modPow(sk.getY1(), p).multiply(g2.modPow(sk.getY2(), p));
			BigInteger h = g1.modPow(sk.getZ(), p);

			return new CramerShoupPublicKeyParameters(csParams, c, d, h);
		}
	}

}