using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.pqc.crypto.qtesla
{
		
	/// <summary>
	/// qTESLA private key
	/// </summary>
	public sealed class QTESLAPrivateKeyParameters : AsymmetricKeyParameter
	{
		/// <summary>
		/// qTESLA Security Category (From 4 To 8)
		/// </summary>
		private int securityCategory;

		/// <summary>
		/// Text of the qTESLA Private Key
		/// </summary>
		private new byte[] privateKey;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="securityCategory"> the security category for the passed in public key data. </param>
		/// <param name="privateKey"> the private key data. </param>
		public QTESLAPrivateKeyParameters(int securityCategory, byte[] privateKey) : base(true)
		{

			if (privateKey.Length != QTESLASecurityCategory.getPrivateSize(securityCategory))
			{
				throw new IllegalArgumentException("invalid key size for security category");
			}

			this.securityCategory = securityCategory;
			this.privateKey = Arrays.clone(privateKey);
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
		/// Return the key's secret value.
		/// </summary>
		/// <returns> key private data. </returns>
		public byte[] getSecret()
		{
			return Arrays.clone(privateKey);
		}
	}

}