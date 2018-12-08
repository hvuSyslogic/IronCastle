using org.bouncycastle.asn1.edec;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.edec
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using EdECObjectIdentifiers = org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using Ed25519PrivateKeyParameters = org.bouncycastle.crypto.@params.Ed25519PrivateKeyParameters;
	using Ed448PrivateKeyParameters = org.bouncycastle.crypto.@params.Ed448PrivateKeyParameters;
	using PrivateKeyInfoFactory = org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
	using EdDSAKey = org.bouncycastle.jcajce.interfaces.EdDSAKey;
	using Arrays = org.bouncycastle.util.Arrays;

	public class BCEdDSAPrivateKey : EdDSAKey, PrivateKey
	{
		internal const long serialVersionUID = 1L;

		[NonSerialized]
		private AsymmetricKeyParameter eddsaPrivateKey;

		private readonly bool hasPublicKey;
		private readonly byte[] attributes;

		public BCEdDSAPrivateKey(AsymmetricKeyParameter privKey)
		{
			this.hasPublicKey = true;
			this.attributes = null;
			this.eddsaPrivateKey = privKey;
		}

		public BCEdDSAPrivateKey(PrivateKeyInfo keyInfo)
		{
			this.hasPublicKey = keyInfo.hasPublicKey();
			this.attributes = (keyInfo.getAttributes() != null) ? keyInfo.getAttributes().getEncoded() : null;

			populateFromPrivateKeyInfo(keyInfo);
		}

		private void populateFromPrivateKeyInfo(PrivateKeyInfo keyInfo)
		{
			ASN1Encodable keyOcts = keyInfo.parsePrivateKey();
			if (EdECObjectIdentifiers_Fields.id_Ed448.Equals(keyInfo.getPrivateKeyAlgorithm().getAlgorithm()))
			{
				eddsaPrivateKey = new Ed448PrivateKeyParameters(ASN1OctetString.getInstance(keyOcts).getOctets(), 0);
			}
			else
			{
				eddsaPrivateKey = new Ed25519PrivateKeyParameters(ASN1OctetString.getInstance(keyOcts).getOctets(), 0);
			}
		}

		public virtual string getAlgorithm()
		{
			return (eddsaPrivateKey is Ed448PrivateKeyParameters) ? "Ed448" : "Ed25519";
		}

		public virtual string getFormat()
		{
			return "PKCS#8";
		}

		public virtual byte[] getEncoded()
		{
			try
			{
				ASN1Set attrSet = ASN1Set.getInstance(attributes);
				PrivateKeyInfo privInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(eddsaPrivateKey, attrSet);

				if (hasPublicKey)
				{
					return privInfo.getEncoded();
				}
				else
				{
					return (new PrivateKeyInfo(privInfo.getPrivateKeyAlgorithm(), privInfo.parsePrivateKey(), attrSet)).getEncoded();
				}
			}
			catch (IOException)
			{
				return null;
			}
		}

		public virtual AsymmetricKeyParameter engineGetKeyParameters()
		{
			return eddsaPrivateKey;
		}

		public override string ToString()
		{
			AsymmetricKeyParameter pubKey;
			if (eddsaPrivateKey is Ed448PrivateKeyParameters)
			{
				pubKey = ((Ed448PrivateKeyParameters)eddsaPrivateKey).generatePublicKey();
			}
			else
			{
				pubKey = ((Ed25519PrivateKeyParameters)eddsaPrivateKey).generatePublicKey();
			}
			return Utils.keyToString("Private Key", getAlgorithm(), pubKey);
		}

		public override bool Equals(object o)
		{
			if (o == this)
			{
				return true;
			}

			if (!(o is BCEdDSAPrivateKey))
			{
				return false;
			}

			BCEdDSAPrivateKey other = (BCEdDSAPrivateKey)o;

			return Arrays.areEqual(other.getEncoded(), this.getEncoded());
		}

		public override int GetHashCode()
		{
			return Arrays.GetHashCode(this.getEncoded());
		}

		private void readObject(ObjectInputStream @in)
		{
			@in.defaultReadObject();

			byte[] enc = (byte[])@in.readObject();

			populateFromPrivateKeyInfo(PrivateKeyInfo.getInstance(enc));
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.defaultWriteObject();

			@out.writeObject(this.getEncoded());
		}
	}

}