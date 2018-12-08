using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.jcajce.provider.asymmetric.rsa
{

	using DERNull = org.bouncycastle.asn1.DERNull;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using RSAPrivateKey = org.bouncycastle.asn1.pkcs.RSAPrivateKey;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using RSAPrivateCrtKeyParameters = org.bouncycastle.crypto.@params.RSAPrivateCrtKeyParameters;
	using KeyUtil = org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// A provider representation for a RSA private key, with CRT factors included.
	/// </summary>
	public class BCRSAPrivateCrtKey : BCRSAPrivateKey, RSAPrivateCrtKey
	{
		internal new const long serialVersionUID = 7834723820638524718L;

		private BigInteger publicExponent;
		private BigInteger primeP;
		private BigInteger primeQ;
		private BigInteger primeExponentP;
		private BigInteger primeExponentQ;
		private BigInteger crtCoefficient;

		/// <summary>
		/// construct a private key from it's org.bouncycastle.crypto equivalent.
		/// </summary>
		/// <param name="key"> the parameters object representing the private key. </param>
		public BCRSAPrivateCrtKey(RSAPrivateCrtKeyParameters key) : base(key)
		{

			this.publicExponent = key.getPublicExponent();
			this.primeP = key.getP();
			this.primeQ = key.getQ();
			this.primeExponentP = key.getDP();
			this.primeExponentQ = key.getDQ();
			this.crtCoefficient = key.getQInv();
		}

		/// <summary>
		/// construct a private key from an RSAPrivateCrtKeySpec
		/// </summary>
		/// <param name="spec"> the spec to be used in construction. </param>
		public BCRSAPrivateCrtKey(RSAPrivateCrtKeySpec spec)
		{
			this.modulus = spec.getModulus();
			this.publicExponent = spec.getPublicExponent();
			this.privateExponent = spec.getPrivateExponent();
			this.primeP = spec.getPrimeP();
			this.primeQ = spec.getPrimeQ();
			this.primeExponentP = spec.getPrimeExponentP();
			this.primeExponentQ = spec.getPrimeExponentQ();
			this.crtCoefficient = spec.getCrtCoefficient();
		}

		/// <summary>
		/// construct a private key from another RSAPrivateCrtKey.
		/// </summary>
		/// <param name="key"> the object implementing the RSAPrivateCrtKey interface. </param>
		public BCRSAPrivateCrtKey(RSAPrivateCrtKey key)
		{
			this.modulus = key.getModulus();
			this.publicExponent = key.getPublicExponent();
			this.privateExponent = key.getPrivateExponent();
			this.primeP = key.getPrimeP();
			this.primeQ = key.getPrimeQ();
			this.primeExponentP = key.getPrimeExponentP();
			this.primeExponentQ = key.getPrimeExponentQ();
			this.crtCoefficient = key.getCrtCoefficient();
		}

		/// <summary>
		/// construct an RSA key from a private key info object.
		/// </summary>
		public BCRSAPrivateCrtKey(PrivateKeyInfo info) : this(RSAPrivateKey.getInstance(info.parsePrivateKey()))
		{
		}

		/// <summary>
		/// construct an RSA key from a ASN.1 RSA private key object.
		/// </summary>
		public BCRSAPrivateCrtKey(RSAPrivateKey key)
		{
			this.modulus = key.getModulus();
			this.publicExponent = key.getPublicExponent();
			this.privateExponent = key.getPrivateExponent();
			this.primeP = key.getPrime1();
			this.primeQ = key.getPrime2();
			this.primeExponentP = key.getExponent1();
			this.primeExponentQ = key.getExponent2();
			this.crtCoefficient = key.getCoefficient();
		}

		/// <summary>
		/// return the encoding format we produce in getEncoded().
		/// </summary>
		/// <returns> the encoding format we produce in getEncoded(). </returns>
		public override string getFormat()
		{
			return "PKCS#8";
		}

		/// <summary>
		/// Return a PKCS8 representation of the key. The sequence returned
		/// represents a full PrivateKeyInfo object.
		/// </summary>
		/// <returns> a PKCS8 representation of the key. </returns>
		public override byte[] getEncoded()
		{
			return KeyUtil.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.rsaEncryption, DERNull.INSTANCE), new RSAPrivateKey(getModulus(), getPublicExponent(), getPrivateExponent(), getPrimeP(), getPrimeQ(), getPrimeExponentP(), getPrimeExponentQ(), getCrtCoefficient()));
		}

		/// <summary>
		/// return the public exponent.
		/// </summary>
		/// <returns> the public exponent. </returns>
		public virtual BigInteger getPublicExponent()
		{
			return publicExponent;
		}

		/// <summary>
		/// return the prime P.
		/// </summary>
		/// <returns> the prime P. </returns>
		public virtual BigInteger getPrimeP()
		{
			return primeP;
		}

		/// <summary>
		/// return the prime Q.
		/// </summary>
		/// <returns> the prime Q. </returns>
		public virtual BigInteger getPrimeQ()
		{
			return primeQ;
		}

		/// <summary>
		/// return the prime exponent for P.
		/// </summary>
		/// <returns> the prime exponent for P. </returns>
		public virtual BigInteger getPrimeExponentP()
		{
			return primeExponentP;
		}

		/// <summary>
		/// return the prime exponent for Q.
		/// </summary>
		/// <returns> the prime exponent for Q. </returns>
		public virtual BigInteger getPrimeExponentQ()
		{
			return primeExponentQ;
		}

		/// <summary>
		/// return the CRT coefficient.
		/// </summary>
		/// <returns> the CRT coefficient. </returns>
		public virtual BigInteger getCrtCoefficient()
		{
			return crtCoefficient;
		}

		public override int GetHashCode()
		{
			return this.getModulus().GetHashCode() ^ this.getPublicExponent().GetHashCode() ^ this.getPrivateExponent().GetHashCode();
		}

		public override bool Equals(object o)
		{
			if (o == this)
			{
				return true;
			}

			if (!(o is RSAPrivateCrtKey))
			{
				return false;
			}

			RSAPrivateCrtKey key = (RSAPrivateCrtKey)o;

			return this.getModulus().Equals(key.getModulus()) && this.getPublicExponent().Equals(key.getPublicExponent()) && this.getPrivateExponent().Equals(key.getPrivateExponent()) && this.getPrimeP().Equals(key.getPrimeP()) && this.getPrimeQ().Equals(key.getPrimeQ()) && this.getPrimeExponentP().Equals(key.getPrimeExponentP()) && this.getPrimeExponentQ().Equals(key.getPrimeExponentQ()) && this.getCrtCoefficient().Equals(key.getCrtCoefficient());
		}

		public override string ToString()
		{
			StringBuffer buf = new StringBuffer();
			string nl = Strings.lineSeparator();

			buf.append("RSA Private CRT Key [").append(RSAUtil.generateKeyFingerprint(this.getModulus())).append("]").append(",[").append(RSAUtil.generateExponentFingerprint(this.getPublicExponent())).append("]").append(nl);
			buf.append("             modulus: ").append(this.getModulus().ToString(16)).append(nl);
			buf.append("     public exponent: ").append(this.getPublicExponent().ToString(16)).append(nl);

			return buf.ToString();
		}
	}

}