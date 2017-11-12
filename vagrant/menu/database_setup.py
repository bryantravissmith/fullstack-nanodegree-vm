import sys

from sqlalchemy import Column, ForeignKey, Integer, String

from sqlalchemy.ext.declarative import declarative_base

from sqlalchemy.orm import relationship

from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

    def serialize(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class Restaurant(Base):

    __tablename__ = 'restaurant'
    name = Column(
        String(80),
        nullable=False
    )
    id = Column(
        Integer,
        primary_key=True
    )
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    def serialize(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class MenuItem(Base):

    __tablename__ = 'menu_item'
    name = Column(
        String(80),
        nullable=False
    )
    id = Column(
        Integer,
        primary_key=True
    )
    course = Column(String(250))
    description = Column(String(250))
    price = Column(String(8))
    restaurant_id = Column(
        Integer,
        ForeignKey('restaurant.id')
    )
    restaurant = relationship(Restaurant)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    def serialize(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


engine = create_engine(
    #'sqlite:///restaurantmenu.db'
    'sqlite:///restaurantmenuwithusers.db'
)

Base.metadata.create_all(engine)
