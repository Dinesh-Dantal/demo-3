using AutoMapper;
using PenToPublic.Models;
using PenToPublic.DTOs;

namespace PenToPublic.Helpers
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            CreateMap<Payment, PaymentResponseDto>()
                .ForMember(dest => dest.UserName, opt => opt.MapFrom(src => src.User.Reg.UserName));
        }
    }
}
