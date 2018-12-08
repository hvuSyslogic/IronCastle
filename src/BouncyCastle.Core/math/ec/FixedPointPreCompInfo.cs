namespace org.bouncycastle.math.ec
{
	/// <summary>
	/// Class holding precomputation data for fixed-point multiplications.
	/// </summary>
	public class FixedPointPreCompInfo : PreCompInfo
	{
		protected internal ECPoint offset = null;

		/// <summary>
		/// Lookup table for the precomputed <seealso cref="ECPoint"/>s used for a fixed point multiplication.
		/// </summary>
		protected internal ECLookupTable lookupTable = null;

		/// <summary>
		/// The width used for the precomputation. If a larger width precomputation
		/// is already available this may be larger than was requested, so calling
		/// code should refer to the actual width.
		/// </summary>
		protected internal int width = -1;

		public virtual ECLookupTable getLookupTable()
		{
			return lookupTable;
		}

		public virtual void setLookupTable(ECLookupTable lookupTable)
		{
			this.lookupTable = lookupTable;
		}

		public virtual ECPoint getOffset()
		{
			return offset;
		}

		public virtual void setOffset(ECPoint offset)
		{
			this.offset = offset;
		}

		public virtual int getWidth()
		{
			return width;
		}

		public virtual void setWidth(int width)
		{
			this.width = width;
		}
	}

}