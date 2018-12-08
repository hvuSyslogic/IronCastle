﻿using BouncyCastle.Core.Port;
using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.agreement
{

	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using ECAlgorithms = org.bouncycastle.math.ec.ECAlgorithms;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;

	/// <summary>
	/// P1363 7.2.2 ECSVDP-DHC
	/// 
	/// ECSVDP-DHC is Elliptic Curve Secret Value Derivation Primitive,
	/// Diffie-Hellman version with cofactor multiplication. It is based on
	/// the work of [DH76], [Mil86], [Kob87], [LMQ98] and [Kal98a]. This
	/// primitive derives a shared secret value from one party's private key
	/// and another party's public key, where both have the same set of EC
	/// domain parameters. If two parties correctly execute this primitive,
	/// they will produce the same output. This primitive can be invoked by a
	/// scheme to derive a shared secret key; specifically, it may be used
	/// with the schemes ECKAS-DH1 and DL/ECKAS-DH2. It does not assume the
	/// validity of the input public key (see also Section 7.2.1).
	/// <para>
	/// Note: As stated P1363 compatibility mode with ECDH can be preset, and
	/// in this case the implementation doesn't have a ECDH compatibility mode
	/// (if you want that just use ECDHBasicAgreement and note they both implement
	/// BasicAgreement!).
	/// </para>
	/// </summary>
	public class ECDHCBasicAgreement : BasicAgreement
	{
		internal ECPrivateKeyParameters key;

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
				throw new IllegalStateException("ECDHC public key has wrong domain parameters");
			}

			BigInteger hd = @params.getH().multiply(key.getD()).mod(@params.getN());

			// Always perform calculations on the exact curve specified by our private key's parameters
			ECPoint pubPoint = ECAlgorithms.cleanPoint(@params.getCurve(), pub.getQ());
			if (pubPoint.isInfinity())
			{
				throw new IllegalStateException("Infinity is not a valid public key for ECDHC");
			}

			ECPoint P = pubPoint.multiply(hd).normalize();

			if (P.isInfinity())
			{
				throw new IllegalStateException("Infinity is not a valid agreement value for ECDHC");
			}

			return P.getAffineXCoord().toBigInteger();
		}
	}

}