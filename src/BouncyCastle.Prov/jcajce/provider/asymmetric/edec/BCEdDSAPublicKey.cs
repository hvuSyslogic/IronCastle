using org.bouncycastle.asn1.edec;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.edec
{

	using EdECObjectIdentifiers = org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using Ed25519PublicKeyParameters = org.bouncycastle.crypto.@params.Ed25519PublicKeyParameters;
	using Ed448PublicKeyParameters = org.bouncycastle.crypto.@params.Ed448PublicKeyParameters;
	using EdDSAKey = org.bouncycastle.jcajce.interfaces.EdDSAKey;
	using Arrays = org.bouncycastle.util.Arrays;

	public class BCEdDSAPublicKey : EdDSAKey, PublicKey
	{
		internal const long serialVersionUID = 1L;

		[NonSerialized]
		private AsymmetricKeyParameter eddsaPublicKey;

		public BCEdDSAPublicKey(AsymmetricKeyParameter pubKey)
		{
			this.eddsaPublicKey = pubKey;
		}

		public BCEdDSAPublicKey(SubjectPublicKeyInfo keyInfo)
		{
			populateFromPubKeyInfo(keyInfo);
		}

		public BCEdDSAPublicKey(byte[] prefix, byte[] rawData)
		{
			int prefixLength = prefix.Length;

			if (Utils.isValidPrefix(prefix, rawData))
			{
				if ((rawData.Length - prefixLength) == Ed448PublicKeyParameters.KEY_SIZE)
				{
					eddsaPublicKey = new Ed448PublicKeyParameters(rawData, prefixLength);
				}
				else if ((rawData.Length - prefixLength) == Ed25519PublicKeyParameters.KEY_SIZE)
				{
					eddsaPublicKey = new Ed25519PublicKeyParameters(rawData, prefixLength);
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
			if (EdECObjectIdentifiers_Fields.id_Ed448.Equals(keyInfo.getAlgorithm().getAlgorithm()))
			{
				eddsaPublicKey = new Ed448PublicKeyParameters(keyInfo.getPublicKeyData().getOctets(), 0);
			}
			else
			{
				eddsaPublicKey = new Ed25519PublicKeyParameters(keyInfo.getPublicKeyData().getOctets(), 0);
			}
		}

		public virtual string getAlgorithm()
		{
			return (eddsaPublicKey is Ed448PublicKeyParameters) ? "Ed448" : "Ed25519";
		}

		public virtual string getFormat()
		{
			return "X.509";
		}

		public virtual byte[] getEncoded()
		{
			if (eddsaPublicKey is Ed448PublicKeyParameters)
			{
				byte[] encoding = new byte[KeyFactorySpi.Ed448Prefix.Length + Ed448PublicKeyParameters.KEY_SIZE];

				JavaSystem.arraycopy(KeyFactorySpi.Ed448Prefix, 0, encoding, 0, KeyFactorySpi.Ed448Prefix.Length);

				((Ed448PublicKeyParameters)eddsaPublicKey).encode(encoding, KeyFactorySpi.Ed448Prefix.Length);

				return encoding;
			}
			else
			{
				byte[] encoding = new byte[KeyFactorySpi.Ed25519Prefix.Length + Ed25519PublicKeyParameters.KEY_SIZE];

				JavaSystem.arraycopy(KeyFactorySpi.Ed25519Prefix, 0, encoding, 0, KeyFactorySpi.Ed25519Prefix.Length);

				((Ed25519PublicKeyParameters)eddsaPublicKey).encode(encoding, KeyFactorySpi.Ed25519Prefix.Length);

				return encoding;
			}
		}

		public virtual AsymmetricKeyParameter engineGetKeyParameters()
		{
			return eddsaPublicKey;
		}

		public override string ToString()
		{
			return Utils.keyToString("Public Key", getAlgorithm(), eddsaPublicKey);
		}

		public override bool Equals(object o)
		{
			if (o == this)
			{
				return true;
			}

			if (!(o is BCEdDSAPublicKey))
			{
				return false;
			}

			BCEdDSAPublicKey other = (BCEdDSAPublicKey)o;

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