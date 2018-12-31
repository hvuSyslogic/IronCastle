using org.bouncycastle.crypto.@params;
using org.bouncycastle.util;

namespace org.bouncycastle.pqc.crypto.newhope
{
		
	public class NHPublicKeyParameters : AsymmetricKeyParameter
	{
		internal readonly byte[] pubData;

		public NHPublicKeyParameters(byte[] pubData) : base(false)
		{
			this.pubData = Arrays.clone(pubData);
		}

		/// <summary>
		/// Return the public key data.
		/// </summary>
		/// <returns> the public key values. </returns>
		public virtual byte[] getPubData()
		{
			return Arrays.clone(pubData);
		}
	}

}