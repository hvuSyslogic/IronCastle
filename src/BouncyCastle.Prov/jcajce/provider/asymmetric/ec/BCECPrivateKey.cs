using org.bouncycastle.jce.interfaces;
using org.bouncycastle.jce.spec;
using org.bouncycastle.asn1.sec;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1;
using org.bouncycastle.math.ec;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.ec
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X962Parameters = org.bouncycastle.asn1.x9.X962Parameters;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using EC5Util = org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
	using ECUtil = org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
	using PKCS12BagAttributeCarrierImpl = org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
	using ProviderConfiguration = org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
	using ECPointEncoder = org.bouncycastle.jce.interfaces.ECPointEncoder;
	using PKCS12BagAttributeCarrier = org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;

	public class BCECPrivateKey : ECPrivateKey, ECPrivateKey, PKCS12BagAttributeCarrier, ECPointEncoder
	{
		internal const long serialVersionUID = 994553197664784084L;

		private string algorithm = "EC";
		private bool withCompression;

		[NonSerialized]
		private BigInteger d;
		[NonSerialized]
		private ECParameterSpec ecSpec;
		[NonSerialized]
		private ProviderConfiguration configuration;
		[NonSerialized]
		private DERBitString publicKey;

		[NonSerialized]
		private PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();

		public BCECPrivateKey()
		{
		}

		public BCECPrivateKey(ECPrivateKey key, ProviderConfiguration configuration)
		{
			this.d = key.getS();
			this.algorithm = key.getAlgorithm();
			this.ecSpec = key.getParams();
			this.configuration = configuration;
		}

		public BCECPrivateKey(string algorithm, ECPrivateKeySpec spec, ProviderConfiguration configuration)
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

			this.configuration = configuration;
		}


		public BCECPrivateKey(string algorithm, ECPrivateKeySpec spec, ProviderConfiguration configuration)
		{
			this.algorithm = algorithm;
			this.d = spec.getS();
			this.ecSpec = spec.getParams();
			this.configuration = configuration;
		}

		public BCECPrivateKey(string algorithm, BCECPrivateKey key)
		{
			this.algorithm = algorithm;
			this.d = key.d;
			this.ecSpec = key.ecSpec;
			this.withCompression = key.withCompression;
			this.attrCarrier = key.attrCarrier;
			this.publicKey = key.publicKey;
			this.configuration = key.configuration;
		}

		public BCECPrivateKey(string algorithm, ECPrivateKeyParameters @params, BCECPublicKey pubKey, ECParameterSpec spec, ProviderConfiguration configuration)
		{
			this.algorithm = algorithm;
			this.d = @params.getD();
			this.configuration = configuration;

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

			this.publicKey = getPublicKeyDetails(pubKey);
		}

		public BCECPrivateKey(string algorithm, ECPrivateKeyParameters @params, BCECPublicKey pubKey, ECParameterSpec spec, ProviderConfiguration configuration)
		{
			this.algorithm = algorithm;
			this.d = @params.getD();
			this.configuration = configuration;

			if (spec == null)
			{
				ECDomainParameters dp = @params.getParameters();
				EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

				this.ecSpec = new ECParameterSpec(ellipticCurve, EC5Util.convertPoint(dp.getG()), dp.getN(), dp.getH().intValue());
			}
			else
			{
				EllipticCurve ellipticCurve = EC5Util.convertCurve(spec.getCurve(), spec.getSeed());

				this.ecSpec = EC5Util.convertSpec(ellipticCurve, spec);
			}

			try
			{
				this.publicKey = getPublicKeyDetails(pubKey);
			}
			catch (Exception)
			{
				this.publicKey = null; // not all curves are encodable
			}
		}

		public BCECPrivateKey(string algorithm, ECPrivateKeyParameters @params, ProviderConfiguration configuration)
		{
			this.algorithm = algorithm;
			this.d = @params.getD();
			this.ecSpec = null;
			this.configuration = configuration;
		}

		public BCECPrivateKey(string algorithm, PrivateKeyInfo info, ProviderConfiguration configuration)
		{
			this.algorithm = algorithm;
			this.configuration = configuration;
			populateFromPrivKeyInfo(info);
		}

		private void populateFromPrivKeyInfo(PrivateKeyInfo info)
		{
			X962Parameters @params = X962Parameters.getInstance(info.getPrivateKeyAlgorithm().getParameters());

			ECCurve curve = EC5Util.getCurve(configuration, @params);
			ecSpec = EC5Util.convertToSpec(@params, curve);

			ASN1Encodable privKey = info.parsePrivateKey();
			if (privKey is ASN1Integer)
			{
				ASN1Integer derD = ASN1Integer.getInstance(privKey);

				this.d = derD.getValue();
			}
			else
			{
				ECPrivateKey ec = ECPrivateKey.getInstance(privKey);

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
			X962Parameters @params = ECUtils.getDomainParametersFromName(ecSpec, withCompression);

			int orderBitLength;
			if (ecSpec == null)
			{
				orderBitLength = ECUtil.getOrderBitLength(configuration, null, this.getS());
			}
			else
			{
				orderBitLength = ECUtil.getOrderBitLength(configuration, ecSpec.getOrder(), this.getS());
			}

			PrivateKeyInfo info;
			ECPrivateKey keyStructure;

			if (publicKey != null)
			{
				keyStructure = new ECPrivateKey(orderBitLength, this.getS(), publicKey, @params);
			}
			else
			{
				keyStructure = new ECPrivateKey(orderBitLength, this.getS(), @params);
			}

			try
			{
				info = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_ecPublicKey, @params), keyStructure);

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

			return configuration.getEcImplicitlyCa();
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
			if (!(o is BCECPrivateKey))
			{
				return false;
			}

			BCECPrivateKey other = (BCECPrivateKey)o;

			return getD().Equals(other.getD()) && (engineGetSpec().Equals(other.engineGetSpec()));
		}

		public override int GetHashCode()
		{
			return getD().GetHashCode() ^ engineGetSpec().GetHashCode();
		}

		public override string ToString()
		{
			return ECUtil.privateKeyToString("EC", d, engineGetSpec());
		}

		private ECPoint calculateQ(ECParameterSpec spec)
		{
			return spec.getG().multiply(d).normalize();
		}

		private DERBitString getPublicKeyDetails(BCECPublicKey pub)
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
			@in.defaultReadObject();

			byte[] enc = (byte[])@in.readObject();

			this.configuration = BouncyCastleProvider.CONFIGURATION;

			populateFromPrivKeyInfo(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(enc)));

			this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.defaultWriteObject();

			@out.writeObject(this.getEncoded());
		}
	}

}