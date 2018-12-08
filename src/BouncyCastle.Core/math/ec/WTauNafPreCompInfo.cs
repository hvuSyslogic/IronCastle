namespace org.bouncycastle.math.ec
{
	/// <summary>
	/// Class holding precomputation data for the WTNAF (Window
	/// <code>&tau;</code>-adic Non-Adjacent Form) algorithm.
	/// </summary>
	public class WTauNafPreCompInfo : PreCompInfo
	{
		/// <summary>
		/// Array holding the precomputed <code>ECPoint.AbstractF2m</code>s used for the
		/// WTNAF multiplication.
		/// </summary>
		protected internal ECPoint.AbstractF2m[] preComp = null;

		public virtual ECPoint.AbstractF2m[] getPreComp()
		{
			return preComp;
		}

		public virtual void setPreComp(ECPoint.AbstractF2m[] preComp)
		{
			this.preComp = preComp;
		}
	}

}