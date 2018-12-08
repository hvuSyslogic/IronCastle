using System.IO;
using BouncyCastle.Core.Port;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.x509;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.rosstandart;
using org.bouncycastle.asn1.ua;
using org.bouncycastle.asn1.edec;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.util
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using ECGOST3410NamedCurves = org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
	using GOST3410PublicKeyAlgParameters = org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
	using EdECObjectIdentifiers = org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
	using ElGamalParameter = org.bouncycastle.asn1.oiw.ElGamalParameter;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using DHParameter = org.bouncycastle.asn1.pkcs.DHParameter;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RSAPublicKey = org.bouncycastle.asn1.pkcs.RSAPublicKey;
	using RosstandartObjectIdentifiers = org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
	using DSTU4145BinaryField = org.bouncycastle.asn1.ua.DSTU4145BinaryField;
	using DSTU4145ECBinary = org.bouncycastle.asn1.ua.DSTU4145ECBinary;
	using DSTU4145NamedCurves = org.bouncycastle.asn1.ua.DSTU4145NamedCurves;
	using DSTU4145Params = org.bouncycastle.asn1.ua.DSTU4145Params;
	using DSTU4145PointEncoder = org.bouncycastle.asn1.ua.DSTU4145PointEncoder;
	using UAObjectIdentifiers = org.bouncycastle.asn1.ua.UAObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DSAParameter = org.bouncycastle.asn1.x509.DSAParameter;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X509ObjectIdentifiers = org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
	using DHPublicKey = org.bouncycastle.asn1.x9.DHPublicKey;
	using DomainParameters = org.bouncycastle.asn1.x9.DomainParameters;
	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using ValidationParams = org.bouncycastle.asn1.x9.ValidationParams;
	using X962Parameters = org.bouncycastle.asn1.x9.X962Parameters;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using X9ECPoint = org.bouncycastle.asn1.x9.X9ECPoint;
	using X9IntegerConverter = org.bouncycastle.asn1.x9.X9IntegerConverter;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using CustomNamedCurves = org.bouncycastle.crypto.ec.CustomNamedCurves;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using DHParameters = org.bouncycastle.crypto.@params.DHParameters;
	using DHPublicKeyParameters = org.bouncycastle.crypto.@params.DHPublicKeyParameters;
	using DHValidationParameters = org.bouncycastle.crypto.@params.DHValidationParameters;
	using DSAParameters = org.bouncycastle.crypto.@params.DSAParameters;
	using DSAPublicKeyParameters = org.bouncycastle.crypto.@params.DSAPublicKeyParameters;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECNamedDomainParameters = org.bouncycastle.crypto.@params.ECNamedDomainParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using Ed25519PublicKeyParameters = org.bouncycastle.crypto.@params.Ed25519PublicKeyParameters;
	using Ed448PublicKeyParameters = org.bouncycastle.crypto.@params.Ed448PublicKeyParameters;
	using ElGamalParameters = org.bouncycastle.crypto.@params.ElGamalParameters;
	using ElGamalPublicKeyParameters = org.bouncycastle.crypto.@params.ElGamalPublicKeyParameters;
	using RSAKeyParameters = org.bouncycastle.crypto.@params.RSAKeyParameters;
	using X25519PublicKeyParameters = org.bouncycastle.crypto.@params.X25519PublicKeyParameters;
	using X448PublicKeyParameters = org.bouncycastle.crypto.@params.X448PublicKeyParameters;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;

	/// <summary>
	/// Factory to create asymmetric public key parameters for asymmetric ciphers from range of
	/// ASN.1 encoded SubjectPublicKeyInfo objects.
	/// </summary>
	public class PublicKeyFactory
	{
		private static Map converters = new HashMap();

		static PublicKeyFactory()
		{
			converters.put(PKCSObjectIdentifiers_Fields.rsaEncryption, new RSAConverter());
			converters.put(PKCSObjectIdentifiers_Fields.id_RSASSA_PSS, new RSAConverter());
			converters.put(X509ObjectIdentifiers_Fields.id_ea_rsa, new RSAConverter());
			converters.put(X9ObjectIdentifiers_Fields.dhpublicnumber, new DHPublicNumberConverter());
			converters.put(PKCSObjectIdentifiers_Fields.dhKeyAgreement, new DHAgreementConverter());
			converters.put(X9ObjectIdentifiers_Fields.id_dsa, new DSAConverter());
			converters.put(OIWObjectIdentifiers_Fields.dsaWithSHA1, new DSAConverter());
			converters.put(OIWObjectIdentifiers_Fields.elGamalAlgorithm, new ElGamalConverter());
			converters.put(X9ObjectIdentifiers_Fields.id_ecPublicKey, new ECConverter());
			converters.put(CryptoProObjectIdentifiers_Fields.gostR3410_2001, new GOST3410_2001Converter());
			converters.put(RosstandartObjectIdentifiers_Fields.id_tc26_gost_3410_12_256, new GOST3410_2012Converter());
			converters.put(RosstandartObjectIdentifiers_Fields.id_tc26_gost_3410_12_512, new GOST3410_2012Converter());
			converters.put(UAObjectIdentifiers_Fields.dstu4145be, new DSTUConverter());
			converters.put(UAObjectIdentifiers_Fields.dstu4145le, new DSTUConverter());
			converters.put(EdECObjectIdentifiers_Fields.id_X25519, new X25519Converter());
			converters.put(EdECObjectIdentifiers_Fields.id_X448, new X448Converter());
			converters.put(EdECObjectIdentifiers_Fields.id_Ed25519, new Ed25519Converter());
			converters.put(EdECObjectIdentifiers_Fields.id_Ed448, new Ed448Converter());
		}

		/// <summary>
		/// Create a public key from a SubjectPublicKeyInfo encoding
		/// </summary>
		/// <param name="keyInfoData"> the SubjectPublicKeyInfo encoding </param>
		/// <returns> the appropriate key parameter </returns>
		/// <exception cref="IOException"> on an error decoding the key </exception>
		public static AsymmetricKeyParameter createKey(byte[] keyInfoData)
		{
			return createKey(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(keyInfoData)));
		}

		/// <summary>
		/// Create a public key from a SubjectPublicKeyInfo encoding read from a stream
		/// </summary>
		/// <param name="inStr"> the stream to read the SubjectPublicKeyInfo encoding from </param>
		/// <returns> the appropriate key parameter </returns>
		/// <exception cref="IOException"> on an error decoding the key </exception>
		public static AsymmetricKeyParameter createKey(InputStream inStr)
		{
			return createKey(SubjectPublicKeyInfo.getInstance((new ASN1InputStream(inStr)).readObject()));
		}

		/// <summary>
		/// Create a public key from the passed in SubjectPublicKeyInfo
		/// </summary>
		/// <param name="keyInfo"> the SubjectPublicKeyInfo containing the key data </param>
		/// <returns> the appropriate key parameter </returns>
		/// <exception cref="IOException"> on an error decoding the key </exception>
		public static AsymmetricKeyParameter createKey(SubjectPublicKeyInfo keyInfo)
		{
			return createKey(keyInfo, null);
		}

		/// <summary>
		/// Create a public key from the passed in SubjectPublicKeyInfo
		/// </summary>
		/// <param name="keyInfo"> the SubjectPublicKeyInfo containing the key data </param>
		/// <param name="defaultParams"> default parameters that might be needed. </param>
		/// <returns> the appropriate key parameter </returns>
		/// <exception cref="IOException"> on an error decoding the key </exception>
		public static AsymmetricKeyParameter createKey(SubjectPublicKeyInfo keyInfo, object defaultParams)
		{
			AlgorithmIdentifier algId = keyInfo.getAlgorithm();
			SubjectPublicKeyInfoConverter converter = (SubjectPublicKeyInfoConverter)converters.get(algId.getAlgorithm());

			if (converter != null)
			{
				return converter.getPublicKeyParameters(keyInfo, defaultParams);
			}
			else
			{
				throw new IOException("algorithm identifier in public key not recognised: " + algId.getAlgorithm());
			}
		}

		public abstract class SubjectPublicKeyInfoConverter
		{
			public abstract AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams);
		}

		public class RSAConverter : SubjectPublicKeyInfoConverter
		{
			public override AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
			{
				RSAPublicKey pubKey = RSAPublicKey.getInstance(keyInfo.parsePublicKey());

				return new RSAKeyParameters(false, pubKey.getModulus(), pubKey.getPublicExponent());
			}
		}

		public class DHPublicNumberConverter : SubjectPublicKeyInfoConverter
		{
			public override AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
			{
				DHPublicKey dhPublicKey = DHPublicKey.getInstance(keyInfo.parsePublicKey());

				BigInteger y = dhPublicKey.getY();

				DomainParameters dhParams = DomainParameters.getInstance(keyInfo.getAlgorithm().getParameters());

				BigInteger p = dhParams.getP();
				BigInteger g = dhParams.getG();
				BigInteger q = dhParams.getQ();

				BigInteger j = null;
				if (dhParams.getJ() != null)
				{
					j = dhParams.getJ();
				}

				DHValidationParameters validation = null;
				ValidationParams dhValidationParms = dhParams.getValidationParams();
				if (dhValidationParms != null)
				{
					byte[] seed = dhValidationParms.getSeed();
					BigInteger pgenCounter = dhValidationParms.getPgenCounter();

					// TODO Check pgenCounter size?

					validation = new DHValidationParameters(seed, pgenCounter.intValue());
				}

				return new DHPublicKeyParameters(y, new DHParameters(p, g, q, j, validation));
			}
		}

		public class DHAgreementConverter : SubjectPublicKeyInfoConverter
		{
			public override AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
			{
				DHParameter @params = DHParameter.getInstance(keyInfo.getAlgorithm().getParameters());
				ASN1Integer derY = (ASN1Integer)keyInfo.parsePublicKey();

				BigInteger lVal = @params.getL();
				int l = lVal == null ? 0 : lVal.intValue();
				DHParameters dhParams = new DHParameters(@params.getP(), @params.getG(), null, l);

				return new DHPublicKeyParameters(derY.getValue(), dhParams);
			}
		}

		public class ElGamalConverter : SubjectPublicKeyInfoConverter
		{
			public override AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
			{
				ElGamalParameter @params = ElGamalParameter.getInstance(keyInfo.getAlgorithm().getParameters());
				ASN1Integer derY = (ASN1Integer)keyInfo.parsePublicKey();

				return new ElGamalPublicKeyParameters(derY.getValue(), new ElGamalParameters(@params.getP(), @params.getG()));
			}
		}

		public class DSAConverter : SubjectPublicKeyInfoConverter
		{
			public override AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
			{
				ASN1Integer derY = (ASN1Integer)keyInfo.parsePublicKey();
				ASN1Encodable de = keyInfo.getAlgorithm().getParameters();

				DSAParameters parameters = null;
				if (de != null)
				{
					DSAParameter @params = DSAParameter.getInstance(de.toASN1Primitive());
					parameters = new DSAParameters(@params.getP(), @params.getQ(), @params.getG());
				}

				return new DSAPublicKeyParameters(derY.getValue(), parameters);
			}
		}

		public class ECConverter : SubjectPublicKeyInfoConverter
		{
			public override AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
			{
				X962Parameters @params = X962Parameters.getInstance(keyInfo.getAlgorithm().getParameters());
				ECDomainParameters dParams;

				if (@params.isNamedCurve())
				{
					ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)@params.getParameters();

					X9ECParameters x9 = CustomNamedCurves.getByOID(oid);
					if (x9 == null)
					{
						x9 = ECNamedCurveTable.getByOID(oid);
					}
					dParams = new ECNamedDomainParameters(oid, x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());
				}
				else if (@params.isImplicitlyCA())
				{
					dParams = (ECDomainParameters)defaultParams;
				}
				else
				{
					X9ECParameters x9 = X9ECParameters.getInstance(@params.getParameters());
					dParams = new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());
				}

				DERBitString bits = keyInfo.getPublicKeyData();
				byte[] data = bits.getBytes();
				ASN1OctetString key = new DEROctetString(data);

				//
				// extra octet string - the old extra embedded octet string
				//
				if (data[0] == 0x04 && data[1] == data.Length - 2 && (data[2] == 0x02 || data[2] == 0x03))
				{
					int qLength = (new X9IntegerConverter()).getByteLength(dParams.getCurve());

					if (qLength >= data.Length - 3)
					{
						try
						{
							key = (ASN1OctetString)ASN1Primitive.fromByteArray(data);
						}
						catch (IOException)
						{
							throw new IllegalArgumentException("error recovering public key");
						}
					}
				}

				X9ECPoint derQ = new X9ECPoint(dParams.getCurve(), key);

				return new ECPublicKeyParameters(derQ.getPoint(), dParams);
			}
		}

		public class GOST3410_2001Converter : SubjectPublicKeyInfoConverter
		{
			public override AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
			{
				DERBitString bits = keyInfo.getPublicKeyData();
				ASN1OctetString key;

				try
				{
					key = (ASN1OctetString)ASN1Primitive.fromByteArray(bits.getBytes());
				}
				catch (IOException)
				{
					throw new IllegalArgumentException("error recovering public key");
				}

				byte[] keyEnc = key.getOctets();

				byte[] x9Encoding = new byte[65];
				x9Encoding[0] = 0x04;
				for (int i = 1; i <= 32; ++i)
				{
					x9Encoding[i] = keyEnc[32 - i];
					x9Encoding[i + 32] = keyEnc[64 - i];
				}

				ASN1ObjectIdentifier paramOID;

				if (keyInfo.getAlgorithm().getParameters() is ASN1ObjectIdentifier)
				{
					paramOID = ASN1ObjectIdentifier.getInstance(keyInfo.getAlgorithm().getParameters());
				}
				else
				{
					GOST3410PublicKeyAlgParameters @params = GOST3410PublicKeyAlgParameters.getInstance(keyInfo.getAlgorithm().getParameters());
					paramOID = @params.getPublicKeyParamSet();
				}

				ECDomainParameters ecDomainParameters = ECGOST3410NamedCurves.getByOID(paramOID);
				return new ECPublicKeyParameters(ecDomainParameters.getCurve().decodePoint(x9Encoding), ecDomainParameters);
			}
		}

		public class GOST3410_2012Converter : SubjectPublicKeyInfoConverter
		{
			public override AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
			{
				ASN1ObjectIdentifier algOid = keyInfo.getAlgorithm().getAlgorithm();
				DERBitString bits = keyInfo.getPublicKeyData();
				ASN1OctetString key;

				try
				{
					key = (ASN1OctetString)ASN1Primitive.fromByteArray(bits.getBytes());
				}
				catch (IOException)
				{
					throw new IllegalArgumentException("error recovering public key");
				}

				byte[] keyEnc = key.getOctets();

				int fieldSize = 32;
				if (algOid.Equals(RosstandartObjectIdentifiers_Fields.id_tc26_gost_3410_12_512))
				{
					fieldSize = 64;
				}

				int keySize = 2 * fieldSize;

				byte[] x9Encoding = new byte[1 + keySize];
				x9Encoding[0] = 0x04;
				for (int i = 1; i <= fieldSize; ++i)
				{
					x9Encoding[i] = keyEnc[fieldSize - i];
					x9Encoding[i + fieldSize] = keyEnc[keySize - i];
				}

				GOST3410PublicKeyAlgParameters gostParams = GOST3410PublicKeyAlgParameters.getInstance(keyInfo.getAlgorithm().getParameters());

				ECDomainParameters ecDomainParameters = ECGOST3410NamedCurves.getByOID(gostParams.getPublicKeyParamSet());
				return new ECPublicKeyParameters(ecDomainParameters.getCurve().decodePoint(x9Encoding), ecDomainParameters);
			}
		}

		public class DSTUConverter : SubjectPublicKeyInfoConverter
		{
			public override AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
			{
				DERBitString bits = keyInfo.getPublicKeyData();
				ASN1OctetString key;

				try
				{
					key = (ASN1OctetString)ASN1Primitive.fromByteArray(bits.getBytes());
				}
				catch (IOException)
				{
					throw new IllegalArgumentException("error recovering public key");
				}

				byte[] keyEnc = key.getOctets();

				if (keyInfo.getAlgorithm().getAlgorithm().Equals(UAObjectIdentifiers_Fields.dstu4145le))
				{
					reverseBytes(keyEnc);
				}

				DSTU4145Params dstuParams = DSTU4145Params.getInstance(keyInfo.getAlgorithm().getParameters());

				ECDomainParameters ecDomain;
				if (dstuParams.isNamedCurve())
				{
					ASN1ObjectIdentifier curveOid = dstuParams.getNamedCurve();

					ecDomain = DSTU4145NamedCurves.getByOID(curveOid);
				}
				else
				{
					DSTU4145ECBinary binary = dstuParams.getECBinary();
					byte[] b_bytes = binary.getB();
					if (keyInfo.getAlgorithm().getAlgorithm().Equals(UAObjectIdentifiers_Fields.dstu4145le))
					{
						reverseBytes(b_bytes);
					}
					DSTU4145BinaryField field = binary.getField();
					ECCurve curve = new ECCurve.F2m(field.getM(), field.getK1(), field.getK2(), field.getK3(), binary.getA(), new BigInteger(1, b_bytes));
					byte[] g_bytes = binary.getG();
					if (keyInfo.getAlgorithm().getAlgorithm().Equals(UAObjectIdentifiers_Fields.dstu4145le))
					{
						reverseBytes(g_bytes);
					}
					ecDomain = new ECDomainParameters(curve, DSTU4145PointEncoder.decodePoint(curve, g_bytes), binary.getN());
				}

				return new ECPublicKeyParameters(DSTU4145PointEncoder.decodePoint(ecDomain.getCurve(), keyEnc), ecDomain);
			}

			public virtual void reverseBytes(byte[] bytes)
			{
				byte tmp;

				for (int i = 0; i < bytes.Length / 2; i++)
				{
					tmp = bytes[i];
					bytes[i] = bytes[bytes.Length - 1 - i];
					bytes[bytes.Length - 1 - i] = tmp;
				}
			}
		}

		public class X25519Converter : SubjectPublicKeyInfoConverter
		{
			public override AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
			{
				return new X25519PublicKeyParameters(getRawKey(keyInfo, defaultParams, X25519PublicKeyParameters.KEY_SIZE), 0);
			}
		}

		public class X448Converter : SubjectPublicKeyInfoConverter
		{
			public override AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
			{
				return new X448PublicKeyParameters(getRawKey(keyInfo, defaultParams, X448PublicKeyParameters.KEY_SIZE), 0);
			}
		}

		public class Ed25519Converter : SubjectPublicKeyInfoConverter
		{
			public override AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
			{
				return new Ed25519PublicKeyParameters(getRawKey(keyInfo, defaultParams, Ed25519PublicKeyParameters.KEY_SIZE), 0);
			}
		}

		public class Ed448Converter : SubjectPublicKeyInfoConverter
		{
			public override AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, object defaultParams)
			{
				return new Ed448PublicKeyParameters(getRawKey(keyInfo, defaultParams, Ed448PublicKeyParameters.KEY_SIZE), 0);
			}
		}

		private static byte[] getRawKey(SubjectPublicKeyInfo keyInfo, object defaultParams, int expectedSize)
		{
			/*
			 * TODO[RFC 8422]
			 * - Require defaultParams == null?
			 * - Require keyInfo.getAlgorithm().getParameters() == null?
			 */
			byte[] result = keyInfo.getPublicKeyData().getOctets();
			if (expectedSize != result.Length)
			{
				throw new RuntimeException("public key encoding has incorrect length");
			}
			return result;
		}
	}

}