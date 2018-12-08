using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.gost
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using GOST3410PublicKeyAlgParameters = org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using GOST3410PrivateKeyParameters = org.bouncycastle.crypto.@params.GOST3410PrivateKeyParameters;
	using GOST3410Util = org.bouncycastle.jcajce.provider.asymmetric.util.GOST3410Util;
	using PKCS12BagAttributeCarrierImpl = org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
	using GOST3410Params = org.bouncycastle.jce.interfaces.GOST3410Params;
	using GOST3410PrivateKey = org.bouncycastle.jce.interfaces.GOST3410PrivateKey;
	using PKCS12BagAttributeCarrier = org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
	using GOST3410ParameterSpec = org.bouncycastle.jce.spec.GOST3410ParameterSpec;
	using GOST3410PrivateKeySpec = org.bouncycastle.jce.spec.GOST3410PrivateKeySpec;
	using GOST3410PublicKeyParameterSetSpec = org.bouncycastle.jce.spec.GOST3410PublicKeyParameterSetSpec;

	public class BCGOST3410PrivateKey : GOST3410PrivateKey, PKCS12BagAttributeCarrier
	{
		internal const long serialVersionUID = 8581661527592305464L;

		private BigInteger x;

		[NonSerialized]
		private GOST3410Params gost3410Spec;
		[NonSerialized]
		private PKCS12BagAttributeCarrier attrCarrier = new PKCS12BagAttributeCarrierImpl();

		public BCGOST3410PrivateKey()
		{
		}

		public BCGOST3410PrivateKey(GOST3410PrivateKey key)
		{
			this.x = key.getX();
			this.gost3410Spec = key.getParameters();
		}

		public BCGOST3410PrivateKey(GOST3410PrivateKeySpec spec)
		{
			this.x = spec.getX();
			this.gost3410Spec = new GOST3410ParameterSpec(new GOST3410PublicKeyParameterSetSpec(spec.getP(), spec.getQ(), spec.getA()));
		}

		public BCGOST3410PrivateKey(PrivateKeyInfo info)
		{
			GOST3410PublicKeyAlgParameters @params = GOST3410PublicKeyAlgParameters.getInstance(info.getPrivateKeyAlgorithm().getParameters());

			ASN1Encodable privKey = info.parsePrivateKey();

			if (privKey is ASN1Integer)
			{
				this.x = ASN1Integer.getInstance(privKey).getPositiveValue();
			}
			else
			{
				ASN1OctetString derX = ASN1OctetString.getInstance(info.parsePrivateKey());
				byte[] keyEnc = derX.getOctets();
				byte[] keyBytes = new byte[keyEnc.Length];

				for (int i = 0; i != keyEnc.Length; i++)
				{
					keyBytes[i] = keyEnc[keyEnc.Length - 1 - i]; // was little endian
				}

				this.x = new BigInteger(1, keyBytes);
			}

			this.gost3410Spec = GOST3410ParameterSpec.fromPublicKeyAlg(@params);
		}

		public BCGOST3410PrivateKey(GOST3410PrivateKeyParameters @params, GOST3410ParameterSpec spec)
		{
			this.x = @params.getX();
			this.gost3410Spec = spec;

			if (spec == null)
			{
				throw new IllegalArgumentException("spec is null");
			}
		}

		public virtual string getAlgorithm()
		{
			return "GOST3410";
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
			PrivateKeyInfo info;
			byte[] keyEnc = this.getX().toByteArray();
			byte[] keyBytes;

			if (keyEnc[0] == 0)
			{
				keyBytes = new byte[keyEnc.Length - 1];
			}
			else
			{
				keyBytes = new byte[keyEnc.Length];
			}

			for (int i = 0; i != keyBytes.Length; i++)
			{
				keyBytes[i] = keyEnc[keyEnc.Length - 1 - i]; // must be little endian
			}

			try
			{
				if (gost3410Spec is GOST3410ParameterSpec)
				{
					info = new PrivateKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers_Fields.gostR3410_94, new GOST3410PublicKeyAlgParameters(new ASN1ObjectIdentifier(gost3410Spec.getPublicKeyParamSetOID()), new ASN1ObjectIdentifier(gost3410Spec.getDigestParamSetOID()))), new DEROctetString(keyBytes));
				}
				else
				{
					info = new PrivateKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers_Fields.gostR3410_94), new DEROctetString(keyBytes));
				}

				return info.getEncoded(ASN1Encoding_Fields.DER);
			}
			catch (IOException)
			{
				return null;
			}
		}

		public virtual GOST3410Params getParameters()
		{
			return gost3410Spec;
		}

		public virtual BigInteger getX()
		{
			return x;
		}

		public override bool Equals(object o)
		{
			if (!(o is GOST3410PrivateKey))
			{
				return false;
			}

			GOST3410PrivateKey other = (GOST3410PrivateKey)o;

			return this.getX().Equals(other.getX()) && this.getParameters().getPublicKeyParameters().Equals(other.getParameters().getPublicKeyParameters()) && this.getParameters().getDigestParamSetOID().Equals(other.getParameters().getDigestParamSetOID()) && compareObj(this.getParameters().getEncryptionParamSetOID(), other.getParameters().getEncryptionParamSetOID());
		}

		private bool compareObj(object o1, object o2)
		{
			if (o1 == o2)
			{
				return true;
			}

			if (o1 == null)
			{
				return false;
			}

			return o1.Equals(o2);
		}

		public override int GetHashCode()
		{
			return this.getX().GetHashCode() ^ gost3410Spec.GetHashCode();
		}

		public override string ToString()
		{
			try
			{
				return GOSTUtil.privateKeyToString("GOST3410", x, ((GOST3410PrivateKeyParameters)GOST3410Util.generatePrivateKeyParameter(this)).getParameters());
			}
			catch (InvalidKeyException e)
			{
				throw new IllegalStateException(e.Message); // should not be possible
			}
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

			string publicKeyParamSetOID = (string)@in.readObject();
			if (!string.ReferenceEquals(publicKeyParamSetOID, null))
			{
				this.gost3410Spec = new GOST3410ParameterSpec(publicKeyParamSetOID, (string)@in.readObject(), (string)@in.readObject());
			}
			else
			{
				this.gost3410Spec = new GOST3410ParameterSpec(new GOST3410PublicKeyParameterSetSpec((BigInteger)@in.readObject(), (BigInteger)@in.readObject(), (BigInteger)@in.readObject()));
				@in.readObject();
				@in.readObject();
			}
			this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.defaultWriteObject();

			if (!string.ReferenceEquals(gost3410Spec.getPublicKeyParamSetOID(), null))
			{
				@out.writeObject(gost3410Spec.getPublicKeyParamSetOID());
				@out.writeObject(gost3410Spec.getDigestParamSetOID());
				@out.writeObject(gost3410Spec.getEncryptionParamSetOID());
			}
			else
			{
				@out.writeObject(null);
				@out.writeObject(gost3410Spec.getPublicKeyParameters().getP());
				@out.writeObject(gost3410Spec.getPublicKeyParameters().getQ());
				@out.writeObject(gost3410Spec.getPublicKeyParameters().getA());
				@out.writeObject(gost3410Spec.getDigestParamSetOID());
				@out.writeObject(gost3410Spec.getEncryptionParamSetOID());
			}
		}
	}

}