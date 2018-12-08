namespace org.bouncycastle.jce.provider
{
	using ReasonFlags = org.bouncycastle.asn1.x509.ReasonFlags;

	/// <summary>
	/// This class helps to handle CRL revocation reasons mask. Each CRL handles a
	/// certain set of revocation reasons.
	/// </summary>
	public class ReasonsMask
	{
		private int _reasons;

		/// <summary>
		/// Constructs are reason mask with the reasons.
		/// </summary>
		/// <param name="reasons"> The reasons. </param>
		public ReasonsMask(ReasonFlags reasons)
		{
			_reasons = reasons.intValue();
		}

		private ReasonsMask(int reasons)
		{
			_reasons = reasons;
		}

		/// <summary>
		/// A reason mask with no reason.
		/// 
		/// </summary>
		public ReasonsMask() : this(0)
		{
		}

		/// <summary>
		/// A mask with all revocation reasons.
		/// </summary>
		internal static readonly ReasonsMask allReasons = new ReasonsMask(ReasonFlags.aACompromise | ReasonFlags.affiliationChanged | ReasonFlags.cACompromise | ReasonFlags.certificateHold | ReasonFlags.cessationOfOperation | ReasonFlags.keyCompromise | ReasonFlags.privilegeWithdrawn | ReasonFlags.unused | ReasonFlags.superseded);

		/// <summary>
		/// Adds all reasons from the reasons mask to this mask.
		/// </summary>
		/// <param name="mask"> The reasons mask to add. </param>
		public virtual void addReasons(ReasonsMask mask)
		{
			_reasons = _reasons | mask.getReasons();
		}

		/// <summary>
		/// Returns <code>true</code> if this reasons mask contains all possible
		/// reasons.
		/// </summary>
		/// <returns> <code>true</code> if this reasons mask contains all possible
		///         reasons. </returns>
		public virtual bool isAllReasons()
		{
			return _reasons == allReasons._reasons ? true : false;
		}

		/// <summary>
		/// Intersects this mask with the given reasons mask.
		/// </summary>
		/// <param name="mask"> The mask to intersect with. </param>
		/// <returns> The intersection of this and teh given mask. </returns>
		public virtual ReasonsMask intersect(ReasonsMask mask)
		{
			ReasonsMask _mask = new ReasonsMask();
			_mask.addReasons(new ReasonsMask(_reasons & mask.getReasons()));
			return _mask;
		}

		/// <summary>
		/// Returns <code>true</code> if the passed reasons mask has new reasons.
		/// </summary>
		/// <param name="mask"> The reasons mask which should be tested for new reasons. </param>
		/// <returns> <code>true</code> if the passed reasons mask has new reasons. </returns>
		public virtual bool hasNewReasons(ReasonsMask mask)
		{
			return ((_reasons | mask.getReasons() ^ _reasons) != 0);
		}

		/// <summary>
		/// Returns the reasons in this mask.
		/// </summary>
		/// <returns> Returns the reasons. </returns>
		public virtual int getReasons()
		{
			return _reasons;
		}
	}

}