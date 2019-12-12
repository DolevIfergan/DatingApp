using System.Linq;
using AutoMapper;
using DatingApp.API.DTOs;
using DatingApp.API.Models;

namespace DatingApp.API.Helpers
{
    public class AutoMapperProfile : Profile
    {
        public AutoMapperProfile()
        {
            CreateMap<User, UserForListDTO>().ForMember( dest => dest.PhotoUrl, opt => opt.MapFrom(src => src.Photos.FirstOrDefault(p => p.IsMain).Url)).ForMember(dest => dest.Age, opt => opt.MapFrom(src => src.DateOfBirth.CalculateAge( )));

            CreateMap<User, UserForDetailedDTO>().ForMember( dest => dest.PhotoUrl, opt => opt.MapFrom(src => src.Photos.FirstOrDefault(p => p.IsMain).Url)).ForMember(dest => dest.Age, opt => opt.MapFrom(src => src.DateOfBirth.CalculateAge( )));

            CreateMap<Photo, PhotoForDetailedDTO>();
            CreateMap<UserForUpdateDTO, User>();
            CreateMap<Photo, PhotoForReturnDto>();
            CreateMap<PhotoForCreationDto, Photo>();
        }
    }
}