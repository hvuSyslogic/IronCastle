using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.pqc.crypto.qtesla
{
		
	/// <summary>
	/// qTESLA public key
	/// </summary>
	public sealed class QTESLAPublicKeyParameters : AsymmetricKeyParameter
	{
		/// <summary>
		/// qTESLA Security Category
		/// </summary>
		private int securityCategory;

		/// <summary>
		/// Text of the qTESLA Public Key
		/// </summary>
		private byte[] publicKey;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="securityCategory"> the security category for the passed in public key data. </param>
		/// <param name="publicKey"> the public key data. </param>
		public QTESLAPublicKeyParameters(int securityCategory, byte[] publicKey) : base(false)
		{

			if (publicKey.Length != QTESLASecurityCategory.getPublicSize(securityCategory))
			{
				throw new IllegalArgumentException("invalid key size for security category");
			}

			this.securityCategory = securityCategory;
			this.publicKey = Arrays.clone(publicKey);

		}

		/// <summary>
		/// Return the security category for this key.
		/// </summary>
		/// <returns> the key's security category. </returns>
		public int getSecurityCategory()
		{
			return this.securityCategory;
		}

		/// <summary>
		/// Return the key's public value.
		/// </summary>
		/// <returns> key public data. </returns>
		public byte[] getPublicData()
		{
			return Arrays.clone(publicKey);
		}
	}

}