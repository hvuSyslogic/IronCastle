using System.IO;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.edec;

namespace org.bouncycastle.crypto.util
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using EdECObjectIdentifiers = org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using RSAPrivateKey = org.bouncycastle.asn1.pkcs.RSAPrivateKey;
	using ECPrivateKey = org.bouncycastle.asn1.sec.ECPrivateKey;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DSAParameter = org.bouncycastle.asn1.x509.DSAParameter;
	using X962Parameters = org.bouncycastle.asn1.x9.X962Parameters;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using DSAParameters = org.bouncycastle.crypto.@params.DSAParameters;
	using DSAPrivateKeyParameters = org.bouncycastle.crypto.@params.DSAPrivateKeyParameters;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECNamedDomainParameters = org.bouncycastle.crypto.@params.ECNamedDomainParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using Ed25519PrivateKeyParameters = org.bouncycastle.crypto.@params.Ed25519PrivateKeyParameters;
	using Ed448PrivateKeyParameters = org.bouncycastle.crypto.@params.Ed448PrivateKeyParameters;
	using RSAKeyParameters = org.bouncycastle.crypto.@params.RSAKeyParameters;
	using RSAPrivateCrtKeyParameters = org.bouncycastle.crypto.@params.RSAPrivateCrtKeyParameters;
	using X25519PrivateKeyParameters = org.bouncycastle.crypto.@params.X25519PrivateKeyParameters;
	using X448PrivateKeyParameters = org.bouncycastle.crypto.@params.X448PrivateKeyParameters;

	/// <summary>
	/// Factory to create ASN.1 private key info objects from lightweight private keys.
	/// </summary>
	public class PrivateKeyInfoFactory
	{
		private PrivateKeyInfoFactory()
		{

		}

		/// <summary>
		/// Create a PrivateKeyInfo representation of a private key.
		/// </summary>
		/// <param name="privateKey"> the key to be encoded into the info object. </param>
		/// <returns> the appropriate PrivateKeyInfo </returns>
		/// <exception cref="IOException"> on an error encoding the key </exception>
		public static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey)
		{
			return createPrivateKeyInfo(privateKey, null);
		}

		/// <summary>
		/// Create a PrivateKeyInfo representation of a private key with attributes.
		/// </summary>
		/// <param name="privateKey"> the key to be encoded into the info object. </param>
		/// <param name="attributes"> the set of attributes to be included. </param>
		/// <returns> the appropriate PrivateKeyInfo </returns>
		/// <exception cref="IOException"> on an error encoding the key </exception>
		public static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey, ASN1Set attributes)
		{
			if (privateKey is RSAKeyParameters)
			{
				RSAPrivateCrtKeyParameters priv = (RSAPrivateCrtKeyParameters)privateKey;

				return new PrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.rsaEncryption, DERNull.INSTANCE), new RSAPrivateKey(priv.getModulus(), priv.getPublicExponent(), priv.getExponent(), priv.getP(), priv.getQ(), priv.getDP(), priv.getDQ(), priv.getQInv()), attributes);
			}
			else if (privateKey is DSAPrivateKeyParameters)
			{
				DSAPrivateKeyParameters priv = (DSAPrivateKeyParameters)privateKey;
				DSAParameters @params = priv.getParameters();

				return new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_dsa, new DSAParameter(@params.getP(), @params.getQ(), @params.getG())), new ASN1Integer(priv.getX()), attributes);
			}
			else if (privateKey is ECPrivateKeyParameters)
			{
				ECPrivateKeyParameters priv = (ECPrivateKeyParameters)privateKey;
				ECDomainParameters domainParams = priv.getParameters();
				ASN1Encodable @params;
				int orderBitLength;

				if (domainParams == null)
				{
					@params = new X962Parameters(DERNull.INSTANCE); // Implicitly CA
					orderBitLength = priv.getD().bitLength(); // TODO: this is as good as currently available, must be a better way...
				}
				else if (domainParams is ECNamedDomainParameters)
				{
					@params = new X962Parameters(((ECNamedDomainParameters)domainParams).getName());
					orderBitLength = domainParams.getN().bitLength();
				}
				else
				{
					X9ECParameters ecP = new X9ECParameters(domainParams.getCurve(), domainParams.getG(), domainParams.getN(), domainParams.getH(), domainParams.getSeed());

					@params = new X962Parameters(ecP);
					orderBitLength = domainParams.getN().bitLength();
				}

				return new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_ecPublicKey, @params), new ECPrivateKey(orderBitLength, priv.getD(), new DERBitString(domainParams.getG().multiply(priv.getD()).getEncoded(false)), @params), attributes);
			}
			else if (privateKey is X448PrivateKeyParameters)
			{
				X448PrivateKeyParameters key = (X448PrivateKeyParameters)privateKey;

				return new PrivateKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers_Fields.id_X448), new DEROctetString(key.getEncoded()), attributes, key.generatePublicKey().getEncoded());
			}
			else if (privateKey is X25519PrivateKeyParameters)
			{
				X25519PrivateKeyParameters key = (X25519PrivateKeyParameters)privateKey;

				return new PrivateKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers_Fields.id_X25519), new DEROctetString(key.getEncoded()), attributes, key.generatePublicKey().getEncoded());
			}
			else if (privateKey is Ed448PrivateKeyParameters)
			{
				Ed448PrivateKeyParameters key = (Ed448PrivateKeyParameters)privateKey;

				return new PrivateKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers_Fields.id_Ed448), new DEROctetString(key.getEncoded()), attributes, key.generatePublicKey().getEncoded());
			}
			else if (privateKey is Ed25519PrivateKeyParameters)
			{
				Ed25519PrivateKeyParameters key = (Ed25519PrivateKeyParameters)privateKey;

				return new PrivateKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers_Fields.id_Ed25519), new DEROctetString(key.getEncoded()), attributes, key.generatePublicKey().getEncoded());
			}
			else
			{
				throw new IOException("key parameters not recognised.");
			}
		}

	}

}