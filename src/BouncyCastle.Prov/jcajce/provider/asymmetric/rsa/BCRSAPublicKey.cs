using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.rsa
{

	using DERNull = org.bouncycastle.asn1.DERNull;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using RSAKeyParameters = org.bouncycastle.crypto.@params.RSAKeyParameters;
	using KeyUtil = org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
	using Strings = org.bouncycastle.util.Strings;

	public class BCRSAPublicKey : RSAPublicKey
	{
		private static readonly AlgorithmIdentifier DEFAULT_ALGORITHM_IDENTIFIER = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.rsaEncryption, DERNull.INSTANCE);

		internal const long serialVersionUID = 2675817738516720772L;

		private BigInteger modulus;
		private BigInteger publicExponent;
		[NonSerialized]
		private AlgorithmIdentifier algorithmIdentifier;

		public BCRSAPublicKey(RSAKeyParameters key)
		{
			this.algorithmIdentifier = DEFAULT_ALGORITHM_IDENTIFIER;
			this.modulus = key.getModulus();
			this.publicExponent = key.getExponent();
		}

		public BCRSAPublicKey(RSAPublicKeySpec spec)
		{
			this.algorithmIdentifier = DEFAULT_ALGORITHM_IDENTIFIER;
			this.modulus = spec.getModulus();
			this.publicExponent = spec.getPublicExponent();
		}

		public BCRSAPublicKey(RSAPublicKey key)
		{
			this.algorithmIdentifier = DEFAULT_ALGORITHM_IDENTIFIER;
			this.modulus = key.getModulus();
			this.publicExponent = key.getPublicExponent();
		}

		public BCRSAPublicKey(SubjectPublicKeyInfo info)
		{
			populateFromPublicKeyInfo(info);
		}

		private void populateFromPublicKeyInfo(SubjectPublicKeyInfo info)
		{
			try
			{
				RSAPublicKey pubKey = RSAPublicKey.getInstance(info.parsePublicKey());

				this.algorithmIdentifier = info.getAlgorithm();
				this.modulus = pubKey.getModulus();
				this.publicExponent = pubKey.getPublicExponent();
			}
			catch (IOException)
			{
				throw new IllegalArgumentException("invalid info structure in RSA public key");
			}
		}

		/// <summary>
		/// return the modulus.
		/// </summary>
		/// <returns> the modulus. </returns>
		public virtual BigInteger getModulus()
		{
			return modulus;
		}

		/// <summary>
		/// return the public exponent.
		/// </summary>
		/// <returns> the public exponent. </returns>
		public virtual BigInteger getPublicExponent()
		{
			return publicExponent;
		}

		public virtual string getAlgorithm()
		{
			return "RSA";
		}

		public virtual string getFormat()
		{
			return "X.509";
		}

		public virtual byte[] getEncoded()
		{
			return KeyUtil.getEncodedSubjectPublicKeyInfo(algorithmIdentifier, new RSAPublicKey(getModulus(), getPublicExponent()));
		}

		public override int GetHashCode()
		{
			return this.getModulus().GetHashCode() ^ this.getPublicExponent().GetHashCode();
		}

		public override bool Equals(object o)
		{
			if (o == this)
			{
				return true;
			}

			if (!(o is RSAPublicKey))
			{
				return false;
			}

			RSAPublicKey key = (RSAPublicKey)o;

			return getModulus().Equals(key.getModulus()) && getPublicExponent().Equals(key.getPublicExponent());
		}

		public override string ToString()
		{
			StringBuffer buf = new StringBuffer();
			string nl = Strings.lineSeparator();

			buf.append("RSA Public Key [").append(RSAUtil.generateKeyFingerprint(this.getModulus())).append("]").append(",[").append(RSAUtil.generateExponentFingerprint(this.getPublicExponent())).append("]").append(nl);
			buf.append("        modulus: ").append(this.getModulus().ToString(16)).append(nl);
			buf.append("public exponent: ").append(this.getPublicExponent().ToString(16)).append(nl);

			return buf.ToString();
		}

		private void readObject(ObjectInputStream @in)
		{
			@in.defaultReadObject();

			try
			{
				algorithmIdentifier = AlgorithmIdentifier.getInstance(@in.readObject());
			}
			catch (Exception)
			{
				algorithmIdentifier = DEFAULT_ALGORITHM_IDENTIFIER;
			}
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.defaultWriteObject();

			if (!algorithmIdentifier.Equals(DEFAULT_ALGORITHM_IDENTIFIER))
			{
				@out.writeObject(algorithmIdentifier.getEncoded());
			}
		}
	}

}