using System.IO;
using org.bouncycastle.asn1;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.edec;
using org.bouncycastle.asn1.sec;
using org.bouncycastle.asn1.x509;
using org.bouncycastle.crypto.@params;

namespace org.bouncycastle.crypto.util
{

																												
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