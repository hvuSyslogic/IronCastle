using BouncyCastle.Core.Port;
using org.bouncycastle.math.ec;
using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.agreement
{

	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using ECAlgorithms = org.bouncycastle.math.ec.ECAlgorithms;
	using ECConstants = org.bouncycastle.math.ec.ECConstants;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;

	/// <summary>
	/// P1363 7.2.1 ECSVDP-DH
	/// 
	/// ECSVDP-DH is Elliptic Curve Secret Value Derivation Primitive,
	/// Diffie-Hellman version. It is based on the work of [DH76], [Mil86],
	/// and [Kob87]. This primitive derives a shared secret value from one
	/// party's private key and another party's public key, where both have
	/// the same set of EC domain parameters. If two parties correctly
	/// execute this primitive, they will produce the same output. This
	/// primitive can be invoked by a scheme to derive a shared secret key;
	/// specifically, it may be used with the schemes ECKAS-DH1 and
	/// DL/ECKAS-DH2. It assumes that the input keys are valid (see also
	/// Section 7.2.2).
	/// </summary>
	public class ECDHBasicAgreement : BasicAgreement
	{
		private ECPrivateKeyParameters key;

		public virtual void init(CipherParameters key)
		{
			this.key = (ECPrivateKeyParameters)key;
		}

		public virtual int getFieldSize()
		{
			return (key.getParameters().getCurve().getFieldSize() + 7) / 8;
		}

		public virtual BigInteger calculateAgreement(CipherParameters pubKey)
		{
			ECPublicKeyParameters pub = (ECPublicKeyParameters)pubKey;
			ECDomainParameters @params = key.getParameters();
			if (!@params.Equals(pub.getParameters()))
			{
				throw new IllegalStateException("ECDH public key has wrong domain parameters");
			}

			BigInteger d = key.getD();

			// Always perform calculations on the exact curve specified by our private key's parameters
			ECPoint Q = ECAlgorithms.cleanPoint(@params.getCurve(), pub.getQ());
			if (Q.isInfinity())
			{
				throw new IllegalStateException("Infinity is not a valid public key for ECDH");
			}

			BigInteger h = @params.getH();
			if (!h.Equals(ECConstants_Fields.ONE))
			{
				d = @params.getHInv().multiply(d).mod(@params.getN());
				Q = ECAlgorithms.referenceMultiply(Q, h);
			}

			ECPoint P = Q.multiply(d).normalize();
			if (P.isInfinity())
			{
				throw new IllegalStateException("Infinity is not a valid agreement value for ECDH");
			}

			return P.getAffineXCoord().toBigInteger();
		}
	}

}