using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.jce.provider
{

	using DERNull = org.bouncycastle.asn1.DERNull;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using RSAKeyParameters = org.bouncycastle.crypto.@params.RSAKeyParameters;
	using KeyUtil = org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
	using Strings = org.bouncycastle.util.Strings;

	public class JCERSAPublicKey : RSAPublicKey
	{
		internal const long serialVersionUID = 2675817738516720772L;

		private BigInteger modulus;
		private BigInteger publicExponent;

		public JCERSAPublicKey(RSAKeyParameters key)
		{
			this.modulus = key.getModulus();
			this.publicExponent = key.getExponent();
		}

		public JCERSAPublicKey(RSAPublicKeySpec spec)
		{
			this.modulus = spec.getModulus();
			this.publicExponent = spec.getPublicExponent();
		}

		public JCERSAPublicKey(RSAPublicKey key)
		{
			this.modulus = key.getModulus();
			this.publicExponent = key.getPublicExponent();
		}

		public JCERSAPublicKey(SubjectPublicKeyInfo info)
		{
			try
			{
				RSAPublicKey pubKey = RSAPublicKey.getInstance(info.parsePublicKey());

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
			return KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.rsaEncryption, DERNull.INSTANCE), new RSAPublicKey(getModulus(), getPublicExponent()));
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

			buf.append("RSA Public Key").append(nl);
			buf.append("            modulus: ").append(this.getModulus().ToString(16)).append(nl);
			buf.append("    public exponent: ").append(this.getPublicExponent().ToString(16)).append(nl);

			return buf.ToString();
		}
	}

}