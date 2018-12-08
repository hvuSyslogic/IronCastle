using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.rsa
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using RSAKeyParameters = org.bouncycastle.crypto.@params.RSAKeyParameters;
	using KeyUtil = org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
	using PKCS12BagAttributeCarrierImpl = org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
	using PKCS12BagAttributeCarrier = org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
	using Strings = org.bouncycastle.util.Strings;

	public class BCRSAPrivateKey : RSAPrivateKey, PKCS12BagAttributeCarrier
	{
		internal const long serialVersionUID = 5110188922551353628L;

		private static BigInteger ZERO = BigInteger.valueOf(0);

		protected internal BigInteger modulus;
		protected internal BigInteger privateExponent;

		[NonSerialized]
		private PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();

		public BCRSAPrivateKey()
		{
		}

		public BCRSAPrivateKey(RSAKeyParameters key)
		{
			this.modulus = key.getModulus();
			this.privateExponent = key.getExponent();
		}

		public BCRSAPrivateKey(RSAPrivateKeySpec spec)
		{
			this.modulus = spec.getModulus();
			this.privateExponent = spec.getPrivateExponent();
		}

		public BCRSAPrivateKey(RSAPrivateKey key)
		{
			this.modulus = key.getModulus();
			this.privateExponent = key.getPrivateExponent();
		}

		public BCRSAPrivateKey(RSAPrivateKey key)
		{
			this.modulus = key.getModulus();
			this.privateExponent = key.getPrivateExponent();
		}

		public virtual BigInteger getModulus()
		{
			return modulus;
		}

		public virtual BigInteger getPrivateExponent()
		{
			return privateExponent;
		}

		public virtual string getAlgorithm()
		{
			return "RSA";
		}

		public virtual string getFormat()
		{
			return "PKCS#8";
		}

		public virtual byte[] getEncoded()
		{
			return KeyUtil.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.rsaEncryption, DERNull.INSTANCE), new RSAPrivateKey(getModulus(), ZERO, getPrivateExponent(), ZERO, ZERO, ZERO, ZERO, ZERO));
		}

		public override bool Equals(object o)
		{
			if (!(o is RSAPrivateKey))
			{
				return false;
			}

			if (o == this)
			{
				return true;
			}

			RSAPrivateKey key = (RSAPrivateKey)o;

			return getModulus().Equals(key.getModulus()) && getPrivateExponent().Equals(key.getPrivateExponent());
		}

		public override int GetHashCode()
		{
			return getModulus().GetHashCode() ^ getPrivateExponent().GetHashCode();
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

		private void readObject(ObjectInputStream @in)
		{
			@in.defaultReadObject();

			this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.defaultWriteObject();
		}

		public override string ToString()
		{
			StringBuffer buf = new StringBuffer();
			string nl = Strings.lineSeparator();

			buf.append("RSA Private Key [").append(RSAUtil.generateKeyFingerprint(this.getModulus())).append("],[]").append(nl);
			buf.append("            modulus: ").append(this.getModulus().ToString(16)).append(nl);

			return buf.ToString();
		}
	}

}