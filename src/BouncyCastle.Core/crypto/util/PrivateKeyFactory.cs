using System.IO;
using BouncyCastle.Core.Port;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.x509;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.edec;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.util
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using EdECObjectIdentifiers = org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
	using ElGamalParameter = org.bouncycastle.asn1.oiw.ElGamalParameter;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using DHParameter = org.bouncycastle.asn1.pkcs.DHParameter;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using RSAPrivateKey = org.bouncycastle.asn1.pkcs.RSAPrivateKey;
	using ECPrivateKey = org.bouncycastle.asn1.sec.ECPrivateKey;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DSAParameter = org.bouncycastle.asn1.x509.DSAParameter;
	using X509ObjectIdentifiers = org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using X962Parameters = org.bouncycastle.asn1.x9.X962Parameters;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using CustomNamedCurves = org.bouncycastle.crypto.ec.CustomNamedCurves;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using DHParameters = org.bouncycastle.crypto.@params.DHParameters;
	using DHPrivateKeyParameters = org.bouncycastle.crypto.@params.DHPrivateKeyParameters;
	using DSAParameters = org.bouncycastle.crypto.@params.DSAParameters;
	using DSAPrivateKeyParameters = org.bouncycastle.crypto.@params.DSAPrivateKeyParameters;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECNamedDomainParameters = org.bouncycastle.crypto.@params.ECNamedDomainParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using Ed25519PrivateKeyParameters = org.bouncycastle.crypto.@params.Ed25519PrivateKeyParameters;
	using Ed448PrivateKeyParameters = org.bouncycastle.crypto.@params.Ed448PrivateKeyParameters;
	using ElGamalParameters = org.bouncycastle.crypto.@params.ElGamalParameters;
	using ElGamalPrivateKeyParameters = org.bouncycastle.crypto.@params.ElGamalPrivateKeyParameters;
	using RSAPrivateCrtKeyParameters = org.bouncycastle.crypto.@params.RSAPrivateCrtKeyParameters;
	using X25519PrivateKeyParameters = org.bouncycastle.crypto.@params.X25519PrivateKeyParameters;
	using X448PrivateKeyParameters = org.bouncycastle.crypto.@params.X448PrivateKeyParameters;

	/// <summary>
	/// Factory for creating private key objects from PKCS8 PrivateKeyInfo objects.
	/// </summary>
	public class PrivateKeyFactory
	{
		/// <summary>
		/// Create a private key parameter from a PKCS8 PrivateKeyInfo encoding.
		/// </summary>
		/// <param name="privateKeyInfoData"> the PrivateKeyInfo encoding </param>
		/// <returns> a suitable private key parameter </returns>
		/// <exception cref="IOException"> on an error decoding the key </exception>
		public static AsymmetricKeyParameter createKey(byte[] privateKeyInfoData)
		{
			return createKey(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(privateKeyInfoData)));
		}

		/// <summary>
		/// Create a private key parameter from a PKCS8 PrivateKeyInfo encoding read from a
		/// stream.
		/// </summary>
		/// <param name="inStr"> the stream to read the PrivateKeyInfo encoding from </param>
		/// <returns> a suitable private key parameter </returns>
		/// <exception cref="IOException"> on an error decoding the key </exception>
		public static AsymmetricKeyParameter createKey(InputStream inStr)
		{
			return createKey(PrivateKeyInfo.getInstance((new ASN1InputStream(inStr)).readObject()));
		}

		/// <summary>
		/// Create a private key parameter from the passed in PKCS8 PrivateKeyInfo object.
		/// </summary>
		/// <param name="keyInfo"> the PrivateKeyInfo object containing the key material </param>
		/// <returns> a suitable private key parameter </returns>
		/// <exception cref="IOException"> on an error decoding the key </exception>
		public static AsymmetricKeyParameter createKey(PrivateKeyInfo keyInfo)
		{
			AlgorithmIdentifier algId = keyInfo.getPrivateKeyAlgorithm();
			ASN1ObjectIdentifier algOID = algId.getAlgorithm();

			if (algOID.Equals(PKCSObjectIdentifiers_Fields.rsaEncryption) || algOID.Equals(PKCSObjectIdentifiers_Fields.id_RSASSA_PSS) || algOID.Equals(X509ObjectIdentifiers_Fields.id_ea_rsa))
			{
				RSAPrivateKey keyStructure = RSAPrivateKey.getInstance(keyInfo.parsePrivateKey());

				return new RSAPrivateCrtKeyParameters(keyStructure.getModulus(), keyStructure.getPublicExponent(), keyStructure.getPrivateExponent(), keyStructure.getPrime1(), keyStructure.getPrime2(), keyStructure.getExponent1(), keyStructure.getExponent2(), keyStructure.getCoefficient());
			}
			// TODO?
	//      else if (algOID.equals(X9ObjectIdentifiers.dhpublicnumber))
			else if (algOID.Equals(PKCSObjectIdentifiers_Fields.dhKeyAgreement))
			{
				DHParameter @params = DHParameter.getInstance(algId.getParameters());
				ASN1Integer derX = (ASN1Integer)keyInfo.parsePrivateKey();

				BigInteger lVal = @params.getL();
				int l = lVal == null ? 0 : lVal.intValue();
				DHParameters dhParams = new DHParameters(@params.getP(), @params.getG(), null, l);

				return new DHPrivateKeyParameters(derX.getValue(), dhParams);
			}
			else if (algOID.Equals(OIWObjectIdentifiers_Fields.elGamalAlgorithm))
			{
				ElGamalParameter @params = ElGamalParameter.getInstance(algId.getParameters());
				ASN1Integer derX = (ASN1Integer)keyInfo.parsePrivateKey();

				return new ElGamalPrivateKeyParameters(derX.getValue(), new ElGamalParameters(@params.getP(), @params.getG()));
			}
			else if (algOID.Equals(X9ObjectIdentifiers_Fields.id_dsa))
			{
				ASN1Integer derX = (ASN1Integer)keyInfo.parsePrivateKey();
				ASN1Encodable de = algId.getParameters();

				DSAParameters parameters = null;
				if (de != null)
				{
					DSAParameter @params = DSAParameter.getInstance(de.toASN1Primitive());
					parameters = new DSAParameters(@params.getP(), @params.getQ(), @params.getG());
				}

				return new DSAPrivateKeyParameters(derX.getValue(), parameters);
			}
			else if (algOID.Equals(X9ObjectIdentifiers_Fields.id_ecPublicKey))
			{
				X962Parameters @params = new X962Parameters((ASN1Primitive)algId.getParameters());

				X9ECParameters x9;
				ECDomainParameters dParams;

				if (@params.isNamedCurve())
				{
					ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)@params.getParameters();

					x9 = CustomNamedCurves.getByOID(oid);
					if (x9 == null)
					{
						x9 = ECNamedCurveTable.getByOID(oid);
					}
					dParams = new ECNamedDomainParameters(oid, x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());
				}
				else
				{
					x9 = X9ECParameters.getInstance(@params.getParameters());
					dParams = new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());
				}

				ECPrivateKey ec = ECPrivateKey.getInstance(keyInfo.parsePrivateKey());
				BigInteger d = ec.getKey();

				return new ECPrivateKeyParameters(d, dParams);
			}
			else if (algOID.Equals(EdECObjectIdentifiers_Fields.id_X25519))
			{
				return new X25519PrivateKeyParameters(getRawKey(keyInfo, X25519PrivateKeyParameters.KEY_SIZE), 0);
			}
			else if (algOID.Equals(EdECObjectIdentifiers_Fields.id_X448))
			{
				return new X448PrivateKeyParameters(getRawKey(keyInfo, X448PrivateKeyParameters.KEY_SIZE), 0);
			}
			else if (algOID.Equals(EdECObjectIdentifiers_Fields.id_Ed25519))
			{
				return new Ed25519PrivateKeyParameters(getRawKey(keyInfo, Ed25519PrivateKeyParameters.KEY_SIZE), 0);
			}
			else if (algOID.Equals(EdECObjectIdentifiers_Fields.id_Ed448))
			{
				return new Ed448PrivateKeyParameters(getRawKey(keyInfo, Ed448PrivateKeyParameters.KEY_SIZE), 0);
			}
			else
			{
				throw new RuntimeException("algorithm identifier in private key not recognised");
			}
		}

		private static byte[] getRawKey(PrivateKeyInfo keyInfo, int expectedSize)
		{
			byte[] result = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
			if (expectedSize != result.Length)
			{
				throw new RuntimeException("private key encoding has incorrect length");
			}
			return result;
		}
	}

}