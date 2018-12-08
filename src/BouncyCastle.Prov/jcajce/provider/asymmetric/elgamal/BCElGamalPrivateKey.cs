using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.elgamal
{


	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ElGamalParameter = org.bouncycastle.asn1.oiw.ElGamalParameter;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using ElGamalPrivateKeyParameters = org.bouncycastle.crypto.@params.ElGamalPrivateKeyParameters;
	using PKCS12BagAttributeCarrierImpl = org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
	using ElGamalPrivateKey = org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
	using PKCS12BagAttributeCarrier = org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
	using ElGamalParameterSpec = org.bouncycastle.jce.spec.ElGamalParameterSpec;
	using ElGamalPrivateKeySpec = org.bouncycastle.jce.spec.ElGamalPrivateKeySpec;

	public class BCElGamalPrivateKey : ElGamalPrivateKey, DHPrivateKey, PKCS12BagAttributeCarrier
	{
		internal const long serialVersionUID = 4819350091141529678L;

		private BigInteger x;

		[NonSerialized]
		private ElGamalParameterSpec elSpec;
		[NonSerialized]
		private PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();

		public BCElGamalPrivateKey()
		{
		}

		public BCElGamalPrivateKey(ElGamalPrivateKey key)
		{
			this.x = key.getX();
			this.elSpec = key.getParameters();
		}

		public BCElGamalPrivateKey(DHPrivateKey key)
		{
			this.x = key.getX();
			this.elSpec = new ElGamalParameterSpec(key.getParams().getP(), key.getParams().getG());
		}

		public BCElGamalPrivateKey(ElGamalPrivateKeySpec spec)
		{
			this.x = spec.getX();
			this.elSpec = new ElGamalParameterSpec(spec.getParams().getP(), spec.getParams().getG());
		}

		public BCElGamalPrivateKey(DHPrivateKeySpec spec)
		{
			this.x = spec.getX();
			this.elSpec = new ElGamalParameterSpec(spec.getP(), spec.getG());
		}

		public BCElGamalPrivateKey(PrivateKeyInfo info)
		{
			ElGamalParameter @params = ElGamalParameter.getInstance(info.getPrivateKeyAlgorithm().getParameters());
			ASN1Integer derX = ASN1Integer.getInstance(info.parsePrivateKey());

			this.x = derX.getValue();
			this.elSpec = new ElGamalParameterSpec(@params.getP(), @params.getG());
		}

		public BCElGamalPrivateKey(ElGamalPrivateKeyParameters @params)
		{
			this.x = @params.getX();
			this.elSpec = new ElGamalParameterSpec(@params.getParameters().getP(), @params.getParameters().getG());
		}

		public virtual string getAlgorithm()
		{
			return "ElGamal";
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
			try
			{
				PrivateKeyInfo info = new PrivateKeyInfo(new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.elGamalAlgorithm, new ElGamalParameter(elSpec.getP(), elSpec.getG())), new ASN1Integer(getX()));

				return info.getEncoded(ASN1Encoding_Fields.DER);
			}
			catch (IOException)
			{
				return null;
			}
		}

		public virtual ElGamalParameterSpec getParameters()
		{
			return elSpec;
		}

		public virtual DHParameterSpec getParams()
		{
			return new DHParameterSpec(elSpec.getP(), elSpec.getG());
		}

		public virtual BigInteger getX()
		{
			return x;
		}

		public override bool Equals(object o)
		{
			if (!(o is DHPrivateKey))
			{
				return false;
			}

			DHPrivateKey other = (DHPrivateKey)o;

			return this.getX().Equals(other.getX()) && this.getParams().getG().Equals(other.getParams().getG()) && this.getParams().getP().Equals(other.getParams().getP()) && this.getParams().getL() == other.getParams().getL();
		}

		public override int GetHashCode()
		{
			return this.getX().GetHashCode() ^ this.getParams().getG().GetHashCode() ^ this.getParams().getP().GetHashCode() ^ this.getParams().getL();
		}

		private void readObject(ObjectInputStream @in)
		{
			@in.defaultReadObject();

			this.elSpec = new ElGamalParameterSpec((BigInteger)@in.readObject(), (BigInteger)@in.readObject());
			this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.defaultWriteObject();

			@out.writeObject(elSpec.getP());
			@out.writeObject(elSpec.getG());
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
	}

}