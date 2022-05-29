class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  validates :password, length: { in: 6..128 }, if: lambda {self.password.present?}
  validates_confirmation_of :password, if: lambda {self.password.present?}

  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable

  def password_required?
    if respond_to?(:reset_password_token)
       return true if reset_password_token.present?
    end
    return true if new_record?
    password.present? || password_confirmation.present?
  end
end
