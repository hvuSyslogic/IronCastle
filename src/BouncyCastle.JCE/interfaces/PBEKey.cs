namespace javax.crypto.interfaces
{

	/// <summary>
	/// The interface to a PBE key.
	/// </summary>
	/// <seealso cref= PBEKeySpec, SecretKey </seealso>
	public interface PBEKey : SecretKey
	{
		/// <summary>
		/// Returns the password.
		/// 
		/// Note: this method should return a copy of the password. It is the
		/// caller's responsibility to zero out the password information after it is
		/// no longer needed.
		/// </summary>
		/// <returns> the password. </returns>
		char[] getPassword();

		/// <summary>
		/// Returns the salt or null if not specified.
		/// 
		/// Note: this method should return a copy of the salt. It is the caller's
		/// responsibility to zero out the salt information after it is no longer
		/// needed.
		/// </summary>
		/// <returns> the salt. </returns>
		byte[] getSalt();

		/// <summary>
		/// Returns the iteration count or 0 if not specified.
		/// </summary>
		/// <returns> the iteration count. </returns>
		int getIterationCount();
	}

}