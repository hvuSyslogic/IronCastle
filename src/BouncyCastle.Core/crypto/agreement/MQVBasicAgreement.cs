using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.agreement
{

					
	public class MQVBasicAgreement : BasicAgreement
	{
		private static readonly BigInteger ONE = BigInteger.valueOf(1);

		internal DHMQVPrivateParameters privParams;

		public virtual void init(CipherParameters key)
		{
			this.privParams = (DHMQVPrivateParameters)key;
		}

		public virtual int getFieldSize()
		{
			return (privParams.getStaticPrivateKey().getParameters().getP().bitLength() + 7) / 8;
		}

		public virtual BigInteger calculateAgreement(CipherParameters pubKey)
		{
			DHMQVPublicParameters pubParams = (DHMQVPublicParameters)pubKey;

			DHPrivateKeyParameters staticPrivateKey = privParams.getStaticPrivateKey();

			if (!privParams.getStaticPrivateKey().getParameters().Equals(pubParams.getStaticPublicKey().getParameters()))
			{
				throw new IllegalStateException("MQV public key components have wrong domain parameters");
			}

			if (privParams.getStaticPrivateKey().getParameters().getQ() == null)
			{
				throw new IllegalStateException("MQV key domain parameters do not have Q set");
			}

			BigInteger agreement = calculateDHMQVAgreement(staticPrivateKey.getParameters(), staticPrivateKey, pubParams.getStaticPublicKey(), privParams.getEphemeralPrivateKey(), privParams.getEphemeralPublicKey(), pubParams.getEphemeralPublicKey());

			if (agreement.Equals(ONE))
			{
				throw new IllegalStateException("1 is not a valid agreement value for MQV");
			}

			return agreement;
		}

		private BigInteger calculateDHMQVAgreement(DHParameters parameters, DHPrivateKeyParameters xA, DHPublicKeyParameters yB, DHPrivateKeyParameters rA, DHPublicKeyParameters tA, DHPublicKeyParameters tB)
		{
			BigInteger q = parameters.getQ();

			int w = (q.bitLength() + 1) / 2;
			BigInteger twoW = BigInteger.valueOf(2).pow(w);

			BigInteger TA = tA.getY().mod(twoW).add(twoW);
			BigInteger SA = rA.getX().add(TA.multiply(xA.getX())).mod(q);
			BigInteger TB = tB.getY().mod(twoW).add(twoW);
			BigInteger Z = tB.getY().multiply(yB.getY().modPow(TB, parameters.getP())).modPow(SA, parameters.getP());

			return Z;
		}
	}

}