namespace org.bouncycastle.tsp
{
	/// <summary>
	/// Exception thrown if a TSP request or response fails to validate.
	/// <para>
	/// If a failure code is associated with the exception it can be retrieved using
	/// the getFailureCode() method.
	/// </para>
	/// </summary>
	public class TSPValidationException : TSPException
	{
		private int failureCode = -1;

		public TSPValidationException(string message) : base(message)
		{
		}

		public TSPValidationException(string message, int failureCode) : base(message)
		{
			this.failureCode = failureCode;
		}

		/// <summary>
		/// Return the failure code associated with this exception - if one is set.
		/// </summary>
		/// <returns> the failure code if set, -1 otherwise. </returns>
		public virtual int getFailureCode()
		{
			return failureCode;
		}
	}

}