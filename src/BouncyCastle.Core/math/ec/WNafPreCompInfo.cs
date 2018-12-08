namespace org.bouncycastle.math.ec
{
	/// <summary>
	/// Class holding precomputation data for the WNAF (Window Non-Adjacent Form)
	/// algorithm.
	/// </summary>
	public class WNafPreCompInfo : PreCompInfo
	{
		/// <summary>
		/// Array holding the precomputed <code>ECPoint</code>s used for a Window
		/// NAF multiplication.
		/// </summary>
		protected internal ECPoint[] preComp = null;

		/// <summary>
		/// Array holding the negations of the precomputed <code>ECPoint</code>s used
		/// for a Window NAF multiplication.
		/// </summary>
		protected internal ECPoint[] preCompNeg = null;

		/// <summary>
		/// Holds an <code>ECPoint</code> representing twice(this). Used for the
		/// Window NAF multiplication to create or extend the precomputed values.
		/// </summary>
		protected internal ECPoint twice = null;

		public virtual ECPoint[] getPreComp()
		{
			return preComp;
		}

		public virtual void setPreComp(ECPoint[] preComp)
		{
			this.preComp = preComp;
		}

		public virtual ECPoint[] getPreCompNeg()
		{
			return preCompNeg;
		}

		public virtual void setPreCompNeg(ECPoint[] preCompNeg)
		{
			this.preCompNeg = preCompNeg;
		}

		public virtual ECPoint getTwice()
		{
			return twice;
		}

		public virtual void setTwice(ECPoint twice)
		{
			this.twice = twice;
		}
	}

}