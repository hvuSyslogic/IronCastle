using org.bouncycastle.jce.interfaces;
using org.bouncycastle.jce.spec;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.jce.provider
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using ECGOST3410NamedCurves = org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using ECPrivateKeyStructure = org.bouncycastle.asn1.sec.ECPrivateKeyStructure;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X962Parameters = org.bouncycastle.asn1.x9.X962Parameters;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using EC5Util = org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
	using ECUtil = org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
	using PKCS12BagAttributeCarrierImpl = org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
	using ECPointEncoder = org.bouncycastle.jce.interfaces.ECPointEncoder;
	using PKCS12BagAttributeCarrier = org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
	using ECNamedCurveSpec = org.bouncycastle.jce.spec.ECNamedCurveSpec;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using Strings = org.bouncycastle.util.Strings;

	public class JCEECPrivateKey : ECPrivateKey, ECPrivateKey, PKCS12BagAttributeCarrier, ECPointEncoder
	{
		private string algorithm = "EC";
		private BigInteger d;
		private ECParameterSpec ecSpec;
		private bool withCompression;

		private DERBitString publicKey;

		private PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();

		public JCEECPrivateKey()
		{
		}

		public JCEECPrivateKey(ECPrivateKey key)
		{
			this.d = key.getS();
			this.algorithm = key.getAlgorithm();
			this.ecSpec = key.getParams();
		}

		public JCEECPrivateKey(string algorithm, ECPrivateKeySpec spec)
		{
			this.algorithm = algorithm;
			this.d = spec.getD();

			if (spec.getParams() != null) // can be null if implicitlyCA
			{
				ECCurve curve = spec.getParams().getCurve();
				EllipticCurve ellipticCurve;

				ellipticCurve = EC5Util.convertCurve(curve, spec.getParams().getSeed());

				this.ecSpec = EC5Util.convertSpec(ellipticCurve, spec.getParams());
			}
			else
			{
				this.ecSpec = null;
			}
		}


		public JCEECPrivateKey(string algorithm, ECPrivateKeySpec spec)
		{
			this.algorithm = algorithm;
			this.d = spec.getS();
			this.ecSpec = spec.getParams();
		}

		public JCEECPrivateKey(string algorithm, JCEECPrivateKey key)
		{
			this.algorithm = algorithm;
			this.d = key.d;
			this.ecSpec = key.ecSpec;
			this.withCompression = key.withCompression;
			this.attrCarrier = key.attrCarrier;
			this.publicKey = key.publicKey;
		}

		public JCEECPrivateKey(string algorithm, ECPrivateKeyParameters @params, JCEECPublicKey pubKey, ECParameterSpec spec)
		{
			this.algorithm = algorithm;
			this.d = @params.getD();

			if (spec == null)
			{
				ECDomainParameters dp = @params.getParameters();
				EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

				this.ecSpec = new ECParameterSpec(ellipticCurve, EC5Util.convertPoint(dp.getG()), dp.getN(), dp.getH().intValue());
			}
			else
			{
				this.ecSpec = spec;
			}

			publicKey = getPublicKeyDetails(pubKey);
		}

		public JCEECPrivateKey(string algorithm, ECPrivateKeyParameters @params, JCEECPublicKey pubKey, ECParameterSpec spec)
		{
			this.algorithm = algorithm;
			this.d = @params.getD();

			if (spec == null)
			{
				ECDomainParameters dp = @params.getParameters();
				EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

				this.ecSpec = new ECParameterSpec(ellipticCurve, EC5Util.convertPoint(dp.getG()), dp.getN(), dp.getH().intValue());
			}
			else
			{
				EllipticCurve ellipticCurve = EC5Util.convertCurve(spec.getCurve(), spec.getSeed());

				this.ecSpec = new ECParameterSpec(ellipticCurve, EC5Util.convertPoint(spec.getG()), spec.getN(), spec.getH().intValue());
			}

			publicKey = getPublicKeyDetails(pubKey);
		}

		public JCEECPrivateKey(string algorithm, ECPrivateKeyParameters @params)
		{
			this.algorithm = algorithm;
			this.d = @params.getD();
			this.ecSpec = null;
		}

		public JCEECPrivateKey(PrivateKeyInfo info)
		{
			populateFromPrivKeyInfo(info);
		}

		private void populateFromPrivKeyInfo(PrivateKeyInfo info)
		{
			X962Parameters @params = new X962Parameters((ASN1Primitive)info.getPrivateKeyAlgorithm().getParameters());

			if (@params.isNamedCurve())
			{
				ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(@params.getParameters());
				X9ECParameters ecP = ECUtil.getNamedCurveByOid(oid);

				if (ecP == null) // GOST Curve
				{
					ECDomainParameters gParam = ECGOST3410NamedCurves.getByOID(oid);
					EllipticCurve ellipticCurve = EC5Util.convertCurve(gParam.getCurve(), gParam.getSeed());

					ecSpec = new ECNamedCurveSpec(ECGOST3410NamedCurves.getName(oid), ellipticCurve, EC5Util.convertPoint(gParam.getG()), gParam.getN(), gParam.getH());
				}
				else
				{
					EllipticCurve ellipticCurve = EC5Util.convertCurve(ecP.getCurve(), ecP.getSeed());

					ecSpec = new ECNamedCurveSpec(ECUtil.getCurveName(oid), ellipticCurve, EC5Util.convertPoint(ecP.getG()), ecP.getN(), ecP.getH());
				}
			}
			else if (@params.isImplicitlyCA())
			{
				ecSpec = null;
			}
			else
			{
				X9ECParameters ecP = X9ECParameters.getInstance(@params.getParameters());
				EllipticCurve ellipticCurve = EC5Util.convertCurve(ecP.getCurve(), ecP.getSeed());

				this.ecSpec = new ECParameterSpec(ellipticCurve, EC5Util.convertPoint(ecP.getG()), ecP.getN(), ecP.getH().intValue());
			}

			ASN1Encodable privKey = info.parsePrivateKey();
			if (privKey is ASN1Integer)
			{
				ASN1Integer derD = ASN1Integer.getInstance(privKey);

				this.d = derD.getValue();
			}
			else
			{
				ECPrivateKeyStructure ec = new ECPrivateKeyStructure((ASN1Sequence)privKey);

				this.d = ec.getKey();
				this.publicKey = ec.getPublicKey();
			}
		}

		public virtual string getAlgorithm()
		{
			return algorithm;
		}

		/// <summary>
		/// return the encoding format we produce in getEncoded().
		/// </summary>
		/// <returns> the string "PKCS#8" </returns>
		public virtual string getFormat()
		{
			return "PKCS#8";
		}

		/// <summary>
		/// Return a PKCS8 representation of the key. The sequence returned
		/// represents a full PrivateKeyInfo object.
		/// </summary>
		/// <returns> a PKCS8 representation of the key. </returns>
		public virtual byte[] getEncoded()
		{
			X962Parameters @params;

			if (ecSpec is ECNamedCurveSpec)
			{
				ASN1ObjectIdentifier curveOid = ECUtil.getNamedCurveOid(((ECNamedCurveSpec)ecSpec).getName());
				if (curveOid == null) // guess it's the OID
				{
					curveOid = new ASN1ObjectIdentifier(((ECNamedCurveSpec)ecSpec).getName());
				}
				@params = new X962Parameters(curveOid);
			}
			else if (ecSpec == null)
			{
				@params = new X962Parameters(DERNull.INSTANCE);
			}
			else
			{
				ECCurve curve = EC5Util.convertCurve(ecSpec.getCurve());

				X9ECParameters ecP = new X9ECParameters(curve, EC5Util.convertPoint(curve, ecSpec.getGenerator(), withCompression), ecSpec.getOrder(), BigInteger.valueOf(ecSpec.getCofactor()), ecSpec.getCurve().getSeed());

				@params = new X962Parameters(ecP);
			}

			PrivateKeyInfo info;
			ECPrivateKeyStructure keyStructure;

			if (publicKey != null)
			{
				keyStructure = new ECPrivateKeyStructure(this.getS(), publicKey, @params);
			}
			else
			{
				keyStructure = new ECPrivateKeyStructure(this.getS(), @params);
			}

			try
			{
				if (algorithm.Equals("ECGOST3410"))
				{
					info = new PrivateKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers_Fields.gostR3410_2001, @params.toASN1Primitive()), keyStructure.toASN1Primitive());
				}
				else
				{

					info = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_ecPublicKey, @params.toASN1Primitive()), keyStructure.toASN1Primitive());
				}

				return info.getEncoded(ASN1Encoding_Fields.DER);
			}
			catch (IOException)
			{
				return null;
			}
		}

		public virtual ECParameterSpec getParams()
		{
			return ecSpec;
		}

		public virtual ECParameterSpec getParameters()
		{
			if (ecSpec == null)
			{
				return null;
			}

			return EC5Util.convertSpec(ecSpec, withCompression);
		}

		public virtual ECParameterSpec engineGetSpec()
		{
			if (ecSpec != null)
			{
				return EC5Util.convertSpec(ecSpec, withCompression);
			}

			return BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
		}

		public virtual BigInteger getS()
		{
			return d;
		}

		public virtual BigInteger getD()
		{
			return d;
		}

		public virtual void setBagAttribute(ASN1ObjectIdentifier oid, ASN1Encodable attribute)
		{
			attrCarrier.setBagAttribute(oid, attribute);
		}

		public virtual ASN1Encodable getBagAttribute(ASN1ObjectIdentifier oid)
		{
			return attrCarrier.getBagAttribute(oid);
		}

		public virtual Enumeration getBagAttributeKeys()
		{
			return attrCarrier.getBagAttributeKeys();
		}

		public virtual void setPointFormat(string style)
		{
		   withCompression = !("UNCOMPRESSED".Equals(style, StringComparison.OrdinalIgnoreCase));
		}

		public override bool Equals(object o)
		{
			if (!(o is JCEECPrivateKey))
			{
				return false;
			}

			JCEECPrivateKey other = (JCEECPrivateKey)o;

			return getD().Equals(other.getD()) && (engineGetSpec().Equals(other.engineGetSpec()));
		}

		public override int GetHashCode()
		{
			return getD().GetHashCode() ^ engineGetSpec().GetHashCode();
		}

		public override string ToString()
		{
			StringBuffer buf = new StringBuffer();
			string nl = Strings.lineSeparator();

			buf.append("EC Private Key").append(nl);
			buf.append("             S: ").append(this.d.ToString(16)).append(nl);

			return buf.ToString();

		}

		private DERBitString getPublicKeyDetails(JCEECPublicKey pub)
		{
			try
			{
				SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(pub.getEncoded()));

				return info.getPublicKeyData();
			}
			catch (IOException)
			{ // should never happen
				return null;
			}
		}

		private void readObject(ObjectInputStream @in)
		{
			byte[] enc = (byte[])@in.readObject();

			populateFromPrivKeyInfo(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(enc)));

			this.algorithm = (string)@in.readObject();
			this.withCompression = @in.readBoolean();
			this.attrCarrier = new PKCS12BagAttributeCarrierImpl();

			attrCarrier.readObject(@in);
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.writeObject(this.getEncoded());
			@out.writeObject(algorithm);
			@out.writeBoolean(withCompression);

			attrCarrier.writeObject(@out);
		}
	}

}