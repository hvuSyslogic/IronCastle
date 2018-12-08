using org.bouncycastle.asn1.edec;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.edec
{

	using EdECObjectIdentifiers = org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using X25519PublicKeyParameters = org.bouncycastle.crypto.@params.X25519PublicKeyParameters;
	using X448PublicKeyParameters = org.bouncycastle.crypto.@params.X448PublicKeyParameters;
	using XDHKey = org.bouncycastle.jcajce.interfaces.XDHKey;
	using Arrays = org.bouncycastle.util.Arrays;

	public class BCXDHPublicKey : XDHKey, PublicKey
	{
		internal const long serialVersionUID = 1L;

		[NonSerialized]
		private AsymmetricKeyParameter xdhPublicKey;

		public BCXDHPublicKey(AsymmetricKeyParameter pubKey)
		{
			this.xdhPublicKey = pubKey;
		}

		public BCXDHPublicKey(SubjectPublicKeyInfo keyInfo)
		{
			populateFromPubKeyInfo(keyInfo);
		}

		public BCXDHPublicKey(byte[] prefix, byte[] rawData)
		{
			int prefixLength = prefix.Length;

			if (Utils.isValidPrefix(prefix, rawData))
			{
				if ((rawData.Length - prefixLength) == X448PublicKeyParameters.KEY_SIZE)
				{
					xdhPublicKey = new X448PublicKeyParameters(rawData, prefixLength);
				}
				else if ((rawData.Length - prefixLength) == X25519PublicKeyParameters.KEY_SIZE)
				{
					xdhPublicKey = new X25519PublicKeyParameters(rawData, prefixLength);
				}
				else
				{
					throw new InvalidKeySpecException("raw key data not recognised");
				}
			}
			else
			{
				throw new InvalidKeySpecException("raw key data not recognised");
			}
		}

		private void populateFromPubKeyInfo(SubjectPublicKeyInfo keyInfo)
		{
			if (EdECObjectIdentifiers_Fields.id_X448.Equals(keyInfo.getAlgorithm().getAlgorithm()))
			{
				xdhPublicKey = new X448PublicKeyParameters(keyInfo.getPublicKeyData().getOctets(), 0);
			}
			else
			{
				xdhPublicKey = new X25519PublicKeyParameters(keyInfo.getPublicKeyData().getOctets(), 0);
			}
		}

		public virtual string getAlgorithm()
		{
			return (xdhPublicKey is X448PublicKeyParameters) ? "X448" : "X25519";
		}

		public virtual string getFormat()
		{
			return "X.509";
		}

		public virtual byte[] getEncoded()
		{
			if (xdhPublicKey is X448PublicKeyParameters)
			{
				byte[] encoding = new byte[KeyFactorySpi.x448Prefix.Length + X448PublicKeyParameters.KEY_SIZE];

				JavaSystem.arraycopy(KeyFactorySpi.x448Prefix, 0, encoding, 0, KeyFactorySpi.x448Prefix.Length);

				((X448PublicKeyParameters)xdhPublicKey).encode(encoding, KeyFactorySpi.x448Prefix.Length);

				return encoding;
			}
			else
			{
				byte[] encoding = new byte[KeyFactorySpi.x25519Prefix.Length + X25519PublicKeyParameters.KEY_SIZE];

				JavaSystem.arraycopy(KeyFactorySpi.x25519Prefix, 0, encoding, 0, KeyFactorySpi.x25519Prefix.Length);

				((X25519PublicKeyParameters)xdhPublicKey).encode(encoding, KeyFactorySpi.x25519Prefix.Length);

				return encoding;
			}
		}

		public virtual AsymmetricKeyParameter engineGetKeyParameters()
		{
			return xdhPublicKey;
		}

		public override string ToString()
		{
			return Utils.keyToString("Public Key", getAlgorithm(), xdhPublicKey);
		}

		public override bool Equals(object o)
		{
			if (o == this)
			{
				return true;
			}

			if (!(o is BCXDHPublicKey))
			{
				return false;
			}

			BCXDHPublicKey other = (BCXDHPublicKey)o;

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

			populateFromPubKeyInfo(SubjectPublicKeyInfo.getInstance(enc));
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.defaultWriteObject();

			@out.writeObject(this.getEncoded());
		}
	}

}