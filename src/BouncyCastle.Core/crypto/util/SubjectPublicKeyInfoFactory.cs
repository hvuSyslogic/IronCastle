using System.IO;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.edec;

namespace org.bouncycastle.crypto.util
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using EdECObjectIdentifiers = org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RSAPublicKey = org.bouncycastle.asn1.pkcs.RSAPublicKey;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DSAParameter = org.bouncycastle.asn1.x509.DSAParameter;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X962Parameters = org.bouncycastle.asn1.x9.X962Parameters;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using X9ECPoint = org.bouncycastle.asn1.x9.X9ECPoint;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using DSAParameters = org.bouncycastle.crypto.@params.DSAParameters;
	using DSAPublicKeyParameters = org.bouncycastle.crypto.@params.DSAPublicKeyParameters;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECNamedDomainParameters = org.bouncycastle.crypto.@params.ECNamedDomainParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using Ed25519PublicKeyParameters = org.bouncycastle.crypto.@params.Ed25519PublicKeyParameters;
	using Ed448PublicKeyParameters = org.bouncycastle.crypto.@params.Ed448PublicKeyParameters;
	using RSAKeyParameters = org.bouncycastle.crypto.@params.RSAKeyParameters;
	using X25519PublicKeyParameters = org.bouncycastle.crypto.@params.X25519PublicKeyParameters;
	using X448PublicKeyParameters = org.bouncycastle.crypto.@params.X448PublicKeyParameters;

	/// <summary>
	/// Factory to create ASN.1 subject public key info objects from lightweight public keys.
	/// </summary>
	public class SubjectPublicKeyInfoFactory
	{
		private SubjectPublicKeyInfoFactory()
		{

		}

		/// <summary>
		/// Create a SubjectPublicKeyInfo public key.
		/// </summary>
		/// <param name="publicKey"> the key to be encoded into the info object. </param>
		/// <returns> a SubjectPublicKeyInfo representing the key. </returns>
		/// <exception cref="IOException"> on an error encoding the key </exception>
		public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey)
		{
			if (publicKey is RSAKeyParameters)
			{
				RSAKeyParameters pub = (RSAKeyParameters)publicKey;

				return new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.rsaEncryption, DERNull.INSTANCE), new RSAPublicKey(pub.getModulus(), pub.getExponent()));
			}
			else if (publicKey is DSAPublicKeyParameters)
			{
				DSAPublicKeyParameters pub = (DSAPublicKeyParameters)publicKey;

				DSAParameter @params = null;
				DSAParameters dsaParams = pub.getParameters();
				if (dsaParams != null)
				{
					@params = new DSAParameter(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());
				}

				return new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_dsa, @params), new ASN1Integer(pub.getY()));
			}
			else if (publicKey is ECPublicKeyParameters)
			{
				ECPublicKeyParameters pub = (ECPublicKeyParameters)publicKey;
				ECDomainParameters domainParams = pub.getParameters();
				ASN1Encodable @params;

				if (domainParams == null)
				{
					@params = new X962Parameters(DERNull.INSTANCE); // Implicitly CA
				}
				else if (domainParams is ECNamedDomainParameters)
				{
					@params = new X962Parameters(((ECNamedDomainParameters)domainParams).getName());
				}
				else
				{
					X9ECParameters ecP = new X9ECParameters(domainParams.getCurve(), domainParams.getG(), domainParams.getN(), domainParams.getH(), domainParams.getSeed());

					@params = new X962Parameters(ecP);
				}

				ASN1OctetString p = (ASN1OctetString)(new X9ECPoint(pub.getQ())).toASN1Primitive();

				return new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_ecPublicKey, @params), p.getOctets());
			}
			else if (publicKey is X448PublicKeyParameters)
			{
				X448PublicKeyParameters key = (X448PublicKeyParameters)publicKey;

				return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers_Fields.id_X448), key.getEncoded());
			}
			else if (publicKey is X25519PublicKeyParameters)
			{
				X25519PublicKeyParameters key = (X25519PublicKeyParameters)publicKey;

				return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers_Fields.id_X25519), key.getEncoded());
			}
			else if (publicKey is Ed448PublicKeyParameters)
			{
				Ed448PublicKeyParameters key = (Ed448PublicKeyParameters)publicKey;

				return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers_Fields.id_Ed448), key.getEncoded());
			}
			else if (publicKey is Ed25519PublicKeyParameters)
			{
				Ed25519PublicKeyParameters key = (Ed25519PublicKeyParameters)publicKey;

				return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers_Fields.id_Ed25519), key.getEncoded());
			}
			else
			{
				throw new IOException("key parameters not recognised.");
			}
		}
	}

}