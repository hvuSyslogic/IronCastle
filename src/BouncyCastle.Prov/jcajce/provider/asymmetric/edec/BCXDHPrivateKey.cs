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
	using X25519PrivateKeyParameters = org.bouncycastle.crypto.@params.X25519PrivateKeyParameters;
	using X448PrivateKeyParameters = org.bouncycastle.crypto.@params.X448PrivateKeyParameters;
	using PrivateKeyInfoFactory = org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
	using XDHKey = org.bouncycastle.jcajce.interfaces.XDHKey;
	using Arrays = org.bouncycastle.util.Arrays;

	public class BCXDHPrivateKey : XDHKey, PrivateKey
	{
		internal const long serialVersionUID = 1L;

		[NonSerialized]
		private AsymmetricKeyParameter xdhPrivateKey;

		private readonly bool hasPublicKey;
		private readonly byte[] attributes;

		public BCXDHPrivateKey(AsymmetricKeyParameter privKey)
		{
			this.hasPublicKey = true;
			this.attributes = null;
			this.xdhPrivateKey = privKey;
		}

		public BCXDHPrivateKey(PrivateKeyInfo keyInfo)
		{
			this.hasPublicKey = keyInfo.hasPublicKey();
			this.attributes = (keyInfo.getAttributes() != null) ? keyInfo.getAttributes().getEncoded() : null;

			populateFromPrivateKeyInfo(keyInfo);
		}

		private void populateFromPrivateKeyInfo(PrivateKeyInfo keyInfo)
		{
			ASN1Encodable keyOcts = keyInfo.parsePrivateKey();
			if (EdECObjectIdentifiers_Fields.id_X448.Equals(keyInfo.getPrivateKeyAlgorithm().getAlgorithm()))
			{
				xdhPrivateKey = new X448PrivateKeyParameters(ASN1OctetString.getInstance(keyOcts).getOctets(), 0);
			}
			else
			{
				xdhPrivateKey = new X25519PrivateKeyParameters(ASN1OctetString.getInstance(keyOcts).getOctets(), 0);
			}
		}

		public virtual string getAlgorithm()
		{
			return (xdhPrivateKey is X448PrivateKeyParameters) ? "X448" : "X25519";
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
				PrivateKeyInfo privInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(xdhPrivateKey, attrSet);

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
			return xdhPrivateKey;
		}

		public override string ToString()
		{
			AsymmetricKeyParameter pubKey;
			if (xdhPrivateKey is X448PrivateKeyParameters)
			{
				pubKey = ((X448PrivateKeyParameters)xdhPrivateKey).generatePublicKey();
			}
			else
			{
				pubKey = ((X25519PrivateKeyParameters)xdhPrivateKey).generatePublicKey();
			}
			return Utils.keyToString("Private Key", getAlgorithm(), pubKey);
		}

		public override bool Equals(object o)
		{
			if (o == this)
			{
				return true;
			}

			if (!(o is BCXDHPrivateKey))
			{
				return false;
			}

			BCXDHPrivateKey other = (BCXDHPrivateKey)o;

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